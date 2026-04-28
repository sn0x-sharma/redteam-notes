---
icon: layer-plus
---

# The AI Stack

## The AI Stack&#x20;

### What You're Actually Looking At

Think of a modern enterprise AI app like a layered sandwich:

```
┌─────────────────────────────────┐
│     User (Web / Mobile / API)   │  ← You start here
├─────────────────────────────────┤
│         API Gateway             │  ← Kong, nginx, Cloudflare — fingerprint headers
├─────────────────────────────────┤
│      Orchestration Layer        │  ← LangChain, CrewAI, AutoGen, LangGraph
├─────────────────────────────────┤
│  RAG Pipeline | Tools | A2A     │  ← Vector DB, MCP tools, agent-to-agent calls
├─────────────────────────────────┤
│       Inference Server          │  ← Ollama, vLLM, TGI (HuggingFace)
├─────────────────────────────────┤
│       Underlying Model          │  ← Llama, Qwen, Gemini, GPT, Claude etc.
└─────────────────────────────────┘
```

**Each layer leaks different info:**

| Layer            | What it leaks                                                 | How to find it                              |
| ---------------- | ------------------------------------------------------------- | ------------------------------------------- |
| API Gateway      | Proxy software, rate limits, upstream identity                | HTTP headers                                |
| Orchestration    | Framework name (LangChain/CrewAI/etc), error messages         | Error triggering, response format analysis  |
| RAG Pipeline     | Vector DB type, chunk size, document names, similarity scores | Probing queries with source citation        |
| Tools            | Available tool names, schemas, permission levels              | MCP schema extraction, prompt interrogation |
| Inference Server | Model name, provider, token counts                            | `/api/health`, response metadata            |
| Model            | Vendor, version, knowledge cutoff, context window             | Behavioral probing                          |

**Key thing about MCP and A2A:** These protocols are literally _designed to advertise themselves_. MCP exposes tool schemas JSON descriptions of what tools exist, what parameters they take, what they return. This is meant for legitimate clients to discover capabilities. As an attacker, you just read those schemas and you have a full map of everything the agent can do. A2A does the same for inter-agent communication. They're self-describing attack surfaces.

***

## Passive Recon

Passive recon = you don't directly interact with the AI. You're looking at things the system is already exposing without you having to poke it.

Two main techniques:

1. HTTP header analysis
2. Source code / git repo mining

***

#### HTTP Header Fingerprinting - NovaTech Example

**Why this works:** Developers are lazy (not an insult, just a fact). Load balancers add debugging headers. Frameworks advertise themselves. Custom headers get left in production. Nobody audits this stuff.

#### Just grab headers, don't even interact with the AI

```bash
curl -s -I http://192.168.50.21/
```

**What NovaTech leaks:**

```
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
X-Powered-By: NovaTech/2.1.0
X-AI-Backend: OpenAI-GPT5.2          ← model provider + version, free intel
X-RAG-Provider: ChromaDB             ← vector DB choice, free intel
```

Just from two custom headers you know:

* They're using OpenAI's API (means they have an API key somewhere, means cloud-dependent, means you can potentially intercept API calls)
* They're using ChromaDB for RAG (self-hosted or managed? check further)
* App version 2.1.0 (check for known vulns in this version)

#### **Hit health endpoints. Nobody secures these.**

```bash
# Common paths that AI apps expose
curl -s http://192.168.50.21/api/health | jq
curl -s http://192.168.50.21/api/status | jq
curl -s http://192.168.50.21/-/health | jq
curl -s http://192.168.50.21/health | jq
```

**NovaTech response:**

```json
{
  "mcp_enabled": true,
  "model": "gpt-5.2-turbo",
  "rag_enabled": false,
  "service": "novatech-customer-assistant",
  "status": "healthy",
  "version": "2.1.0"
}
```

You now know:

* Exact model: `gpt-5.2-turbo`
* MCP is ON this means the AI has tools it can call. This is a priority target for tool enumeration
* RAG is currently off (so no document injection vector here, look elsewhere)

#### **Confirm the API interface**

```bash
# Does it speak OpenAI API format?
curl -s -X POST http://192.168.50.21/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Hello"}]}' | jq
```

**Response structure tells you a lot:**

```json
{
  "model": "gpt-5.2-turbo",
  "rag_sources": null,          ← RAG is indeed off, null sources
  "usage": {
    "prompt_tokens": 297,       ← 297 tokens just for "Hello" = massive system prompt
    "completion_tokens": 50
  }
}
```

That `prompt_tokens: 297` for a one-word message means there's a system prompt eating \~290 tokens. That's something worth extracting later.

### **Alternative methods to discover API format:**

```bash
# Check for Swagger/OpenAPI docs (devs often leave these exposed)
curl -s http://192.168.50.21/docs
curl -s http://192.168.50.21/openapi.json
curl -s http://192.168.50.21/swagger.json
curl -s http://192.168.50.21/api/docs

# Ollama-specific endpoint
curl -s http://192.168.50.21/api/tags    # lists available models in Ollama

# vLLM-specific
curl -s http://192.168.50.21/v1/models   # lists loaded models

# TGI-specific
curl -s http://192.168.50.21/info        # model info
```

### **Endpoint fuzzing - 401 vs 404 trick:**

```bash
# 404 = endpoint doesn't exist at all
# 401 = endpoint EXISTS but needs auth
# This lets you map the API surface without credentials

for endpoint in auth billing "chat/completions" models users admin config; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    http://192.168.50.21/v1/$endpoint)
  echo "/v1/$endpoint → HTTP $code"
done
```

Output:

```
/v1/auth              → HTTP 200
/v1/billing           → HTTP 200
/v1/chat/completions  → HTTP 401    ← exists, needs auth
/v1/models            → HTTP 404    ← doesn't exist
/v1/users             → HTTP 404
/v1/admin             → HTTP 403    ← exists AND has specific auth requirements
/v1/config            → HTTP 401    ← bonus find
```

`401` on `/v1/chat/completions` tells you: there's a real AI endpoint here, it's OpenAI-compatible, and you need a bearer token. Go find that token.

***

#### Git Repo Mining - NovaTech's Aurora & Phoenix

This is where it gets really good. AI applications have to store configuration somewhere and that somewhere is usually a git repo. And devs commit way more than they should.

**What you're hunting for in AI repos:**

| File                                  | What it reveals                                                                                                    |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `requirements.txt` / `pyproject.toml` | Full tech stack fingerprint                                                                                        |
| `config/rag.yaml`                     | Vector DB, embedding model, chunk size, retrieval thresholds                                                       |
| `prompts/system.txt`                  | System prompt, restrictions, persona, what topics are forbidden                                                    |
| `config/safety.yaml`                  | Guardrail rules, blocked topics, what bypass to target                                                             |
| `.env.example`                        | API key names, service endpoints, integration URLs                                                                 |
| `config/models.yaml`                  | Exact model, GPU config, quantization method                                                                       |
| `src/agents/tools.py`                 | Tool definitions, what the agent can do                                                                            |
| `git log`                             | Commit history — devs sometimes commit real secrets, then delete in next commit (but git history keeps everything) |

#### **Clone the repos**

```bash
git clone http://192.168.50.22/aurora/support-assistant.git
git clone http://192.168.50.22/phoenix/code-reviewer.git
```

#### **Read requirements.txt - instant full stack fingerprint**

Aurora's `requirements.txt`:

```
google-generativeai>=0.8.0    ← Gemini API
crewai>=0.41.0                ← CrewAI agent framework
pinecone-client>=3.0.0        ← Pinecone vector DB (managed, cloud)
google-cloud-aiplatform>=1.38.0
fastapi>=0.109.0
```

Phoenix's `requirements.txt`:

```
vllm>=0.6.0                   ← self-hosted inference (big deal — model is local)
pyautogen>=0.2.0              ← AutoGen framework
pymilvus>=2.4.0               ← Milvus vector DB (self-hosted)
sentence-transformers>=2.3.0
huggingface-hub>=0.20.0       ← pulls model from HuggingFace
autoawq>=0.2.0                ← quantization (running on GPU)
```

**Why cloud vs self-hosted matters for your attack:**

_Cloud-based (Aurora):_

* Has API keys hardcoded or in env vars → find those keys
* Outbound connections to Google/Pinecone → potential MITM if you're in position
* Third-party dependency risks — if Google/Pinecone gets compromised, so does this app
* No GPU required, cheaper to run, but all data goes to Google's servers

_Self-hosted (Phoenix):_

* Model and data never leave the network → you need internal access
* API keys for external services are less of a concern
* But: Milvus DB authentication is often misconfigured → direct DB access possible
* vLLM has its own API, often exposed internally without auth
* The model weights themselves are a target (model theft)

#### **RAG config this tells you exactly how to poison it later**

Aurora's `config/rag.yaml`:

```yaml
chunking:
  strategy: "text"
  chunk_size: 512          ← max 512 chars per chunk
  chunk_overlap: 100       ← chunks overlap by 100 chars (important for injection sizing)

embeddings:
  model: "text-embedding-004"
  dimensions: 768

retrieval:
  top_k: 5                 ← returns top 5 most relevant chunks
  score_threshold: 0.75    ← must be 75%+ similar to be retrieved
  distance_metric: "cosine"
```

**What this means for attacks:**

* `chunk_size: 512` → your injected poisoned document needs to fit within 512 chars to be its own chunk (won't get split mid-injection)
* `score_threshold: 0.75` → your poisoned content needs to be semantically similar enough to target queries to actually get retrieved
* `top_k: 5` → you're competing with 5 other retrieved chunks your injection needs to be relevant enough to rank in top 5

Phoenix's config shows `chunk_size: 1500` with AST-aware chunking it parses code structure (functions, classes, imports) rather than just splitting on character count. Means you'd need code-shaped injections to get past it.

#### **Tool definitions what can the agent actually do?**

Aurora's `src/agents/tools.py`:

```python
from crewai import tool

@tool
def knowledge_search(query: str, department: str) -> str:
    """Search customer documentation and knowledge base."""

@tool
def ticket_lookup(ticket_id: str) -> dict:
    """Look up support ticket status and history."""

@tool
def escalate_ticket(ticket_id: str, reason: str) -> str:
    """Escalate ticket to human agent (create only)"""
```

Phoenix's `prompts/function_schemas.json`:

```json
{
  "functions": [
    {
      "name": "search_codebase",
      "description": "Semantic search across indexed repositories",
      "parameters": {"query": "string", "language": "string", "max_results": "int"}
    },
    {
      "name": "post_review_comment",
      "description": "Post inline comment on merge request",
      "parameters": {"repo": "string", "mr_id": "int", "file_path": "string"}
    },
    {
      "name": "run_security_scan",
      "description": "Run SAST security scanner on code (read-only)"
    }
  ]
}
```

**Why tool definitions matter:** If you can inject instructions into these agents via prompt injection later, you know exactly what you can make them do. Aurora can create support tickets (social engineering escalation path) and search the internal knowledge base. Phoenix can post comments on merge requests (code injection if you can manipulate what it says) and run security scans.

#### **System prompt your bypass roadmap**

Aurora's `prompts/system.txt`:

```
## Restrictions - DO NOT:
- Promise features that are not yet released
- Discuss pricing, discounts, or negotiate contracts
- Share internal documentation or employee information  ← note this
- Compare NovaTech products to competitors
- Discuss security vulnerabilities or ongoing incidents ← note this
```

Phoenix's `prompts/system.txt`:

```
## CRITICAL RESTRICTIONS
- NEVER approve PRs automatically - human approval always required
- NEVER execute or test code - static analysis only
- NEVER access repositories outside the allowlist
```

This is your bypass target list. Phoenix can't auto-approve PRs but what if you can trick it into saying "LGTM" in a way that bypasses the output validator? Let's look at those guardrails.

#### **Guardrails understand the gate before you try to open it**

Phoenix's `config/safety.yaml`:

```yaml
output_parsers:
  - name: "no_approval_validator"
    type: "regex"
    block_patterns:
      - "LGTM"
      - "approved"
      - "merge approved"
      - "ship it"
      - "looks good to me"
```

This is a regex-based guardrail. It blocks outputs containing those exact strings. That's super easy to bypass:

* "This code is acceptable for merging"not in the list
* "Review complete, no issues found" not in the list
* "LGTM" written as "L G T M" not in the list
* Unicode homoglyphs "LＧТМ"  not in the list

#### &#x20;**`.env.example`  API key formats + integration endpoints**

Aurora's `.env.example`:

```
GOOGLE_API_KEY=your_google_api_key_here
PINECONE_API_KEY=your_pinecone_api_key_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
SLACK_CHANNEL=#support-escalations
```

You now know:

* There's a real Slack webhook somewhere if you find the actual value, you can post to their support channel
* Pinecone API key format → search GitHub, Slack history, CI/CD logs for `PINECONE_API_KEY=pk_`
* Internal escalation channel: `#support-escalations` social engineering target

#### **Git history  the nuclear option:**

```bash
cd support-assistant

# See all commits
git log --oneline

# Search entire history for secrets (not just current state)
git log -p | grep -i "api_key\|password\|secret\|token" 

# Show a specific commit
git show <commit_hash>

# Alternative: use trufflehog to scan the entire repo history
trufflehog git file://. --only-verified

# Or gitleaks
gitleaks detect --source . --verbose
```

Devs frequently:

1. Commit real API keys
2. Realize their mistake
3. Delete the file in the next commit

But git history keeps everything. The key is gone from the current state but still accessible in commit history. Trufflehog and gitleaks both scan the full history.

***
