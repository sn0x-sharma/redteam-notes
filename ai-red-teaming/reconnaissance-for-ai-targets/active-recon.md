---
icon: wave-pulse
---

# Active Recon

## Active Recon

Active recon = you're actually talking to the system. Every request generates a log. Do this carefully.

Three areas:

1. AI service discovery
2. Model fingerprinting
3. RAG pipeline probing

***

#### AI Service Discovery

AI is usually embedded in web apps, not running on obvious separate ports. So you can't just `nmap` and find "AI service on port 1337." You have to dig into the web app itself.

**Step 1: Find JavaScript files  they leak config**

```bash
# Find all JS files loaded by the page
curl -s http://192.168.50.31/ | grep -iE "<script"
```

Output:

```html
<script src="js/chat-widget.js"></script>
<script src="js/main.js"></script>
```

The chat widget one is gold. Let's read it:

```bash
curl -s http://192.168.50.31/js/chat-widget.js
```

```javascript
window.__NOVATECH_CONFIG__ = {
    apiBase: "/api/v2",
    assistantEndpoint: "/api/v2/assistant",   ← found the AI endpoint
    featureFlags: {
        enableAI: true,
        debugMode: false,
        legacySupport: true
    },
    timeout: 30000    ← 30s timeout = probably runs a slower local model
};
```

Note the comment: `// Internal Use Only - Do Not Distribute` lmao. It's served publicly.

#### &#x20;**Hit the discovered endpoint**

```bash
curl -s -X POST http://192.168.50.31/api/v2/assistant \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello"}' | jq
```

Response:

```json
{
  "content": "How can I assist you today?",
  "metadata": {
    "provider": "ollama",         ← self-hosted, local model
    "model": "llama3.2:1b",       ← specific model version
    "latency_ms": 418,
    "prompt_eval_count": 26,      ← tiny prompt, probably minimal system prompt
    "eval_count": 8               ← very short generation = small model
  }
}
```

That metadata block is a developer debugging oversight. They returned the full upstream Ollama response object. This is an extremely common mistake the backend calls Ollama, Ollama returns a rich JSON object, the developer just passes it straight through instead of filtering it. You get model identity for free.

**Alternative discovery methods:**

```bash
# If the app uses GraphQL (common in modern enterprise apps)
curl -s -X POST http://192.168.50.31/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# Look for hidden forms/buttons in HTML source
curl -s http://192.168.50.31/ | grep -i "data-endpoint\|data-api\|data-url"

# Check robots.txt — sometimes reveals API paths
curl -s http://192.168.50.31/robots.txt

# Check sitemap
curl -s http://192.168.50.31/sitemap.xml

# Fuzz for hidden paths using a wordlist
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u http://192.168.50.31/FUZZ \
     -mc 200,401,403 -o api_discovery.json

# If there's an Ollama deployment exposed (port 11434)
curl -s http://192.168.50.31:11434/api/tags   # lists all available models
curl -s http://192.168.50.31:11434/api/show -d '{"name":"llama3.2:1b"}'  # model details
```

**Checking the Kong API gateway (port 8000):**

```bash
curl -sI http://192.168.50.31:8000/v1/billing
```

Headers reveal:

```
Server: kong/3.9.1
X-Kong-Upstream-Latency: 10
X-Kong-Proxy-Latency: 37
Via: 1.1 kong/3.9.1
```

Now do the 401 vs 404 enumeration:

```bash
for endpoint in auth billing "chat/completions" models users admin config; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    http://192.168.50.31:8000/v1/$endpoint)
  echo "/v1/$endpoint → HTTP $code"
done
```

```
/v1/auth              → HTTP 200
/v1/billing           → HTTP 200
/v1/chat/completions  → HTTP 401    ← protected AI endpoint exists
/v1/models            → HTTP 404
/v1/users             → HTTP 404
```

The `401` on `/v1/chat/completions` through Kong means there's an OpenAI-compatible AI endpoint sitting behind an API gateway, requiring authentication. Your next step: find a valid API key.

***
