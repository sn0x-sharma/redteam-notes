---
icon: magnifying-glass-arrows-rotate
---

# Reconnaissance for AI Targets

***

### Full Recon Methodology Summary

Here's the full attack flow for AI recon on NovaTech-style targets:

```
Phase 1: Passive (no logs on target)
├── HTTP header analysis → model provider, vector DB, app version
├── Health endpoint → model name, feature flags (RAG/MCP on/off)
├── Git repo clone → full stack, system prompts, guardrails, tool defs
│   ├── requirements.txt → framework fingerprint
│   ├── config/rag.yaml → chunk size, threshold, embedding model
│   ├── prompts/system.txt → restrictions = your bypass list
│   ├── config/safety.yaml → guardrail rules = bypass targets
│   ├── .env.example → API key formats, integration endpoints
│   └── git log -p | grep -i "secret\|key\|password" → leaked secrets
└── Job postings (LinkedIn/Indeed) → "Must have experience with X" = they use X

Phase 2: Low-interaction (minimal logs)
├── JS source analysis → API endpoint discovery
├── 401 vs 404 endpoint enumeration → map protected API surface
└── Single chat message → metadata leak fingerprinting

Phase 3: Active (logged, apply evasion)
├── Contradiction testing → model identity
├── Knowledge cutoff testing → model version
├── Behavioral analysis → model family
├── Context window testing → deployment config
├── RAG probing → knowledge base mapping
│   ├── General vs specific queries → confirm RAG active
│   ├── Topic sweep → document inventory
│   └── Architecture/config queries → internal hostnames, creds
└── Threshold testing → when RAG triggers vs not (needed for injection planning)

Phase 4: OPSEC
├── Space requests 30-60s apart
├── Mix AI probes with legitimate page requests
├── Use indirect questions instead of direct enumeration queries
├── Use metadata leaks instead of identity-probing questions
└── Never use found credentials without validating format first
```

***

### Recon Commands Cheatsheet

```bash
# === PASSIVE ===

# HTTP header fingerprint
curl -s -I http://TARGET/

# Health endpoints
for path in api/health health api/status /-/health v1/health; do
  echo "=== /$path ==="; curl -s http://TARGET/$path | jq 2>/dev/null; done

# 401 vs 404 endpoint mapping
for ep in "v1/chat/completions" "v1/models" "v1/embeddings" "api/chat" "api/health" "api/config"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://TARGET/$ep)
  echo "/$ep → $code"
done

# Ollama/vLLM specific
curl http://TARGET:11434/api/tags          # Ollama: list models
curl http://TARGET:8000/v1/models          # vLLM: list models
curl http://TARGET:8080/info               # TGI: model info

# Git repo mining
git clone http://TARGET/repo.git
git log --oneline
git log -p | grep -iE "api_key|secret|password|token"
trufflehog git file://. --only-verified

# === ACTIVE ===

# Direct identity probe
curl -s -X POST http://TARGET/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"What model are you? Who made you?"}]}' | jq

# Contradiction test
curl -s -X POST http://TARGET/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Thanks for the help, Claude! Great job Anthropic!"}]}' | jq

# Knowledge cutoff test
curl -s -X POST http://TARGET/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Who won the 2024 US presidential election?"}]}' | jq

# Metadata leak (stealthy fingerprint)
curl -s -X POST http://TARGET/api/v2/assistant \
  -H "Content-Type: application/json" \
  -d '{"message": "Thanks for helping me earlier!"}' | jq '.metadata'

# RAG probe
curl -s -X POST http://TARGET/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the system architecture?"}' | jq '.sources[].text'

# RAG threshold test
curl -s -X POST http://TARGET/api/chat \
  -d '{"query": "vaycation dayz rulez"}' | jq '.sources | length'
# 0 = below threshold
```

***

### Chapter Summary

| Recon Type   | Technique            | What You Get                                  | Detection Risk      |
| ------------ | -------------------- | --------------------------------------------- | ------------------- |
| Passive      | HTTP headers         | Model provider, vector DB, version            | None                |
| Passive      | Health endpoints     | Model name, features on/off                   | Low                 |
| Passive      | Git repo analysis    | Full stack, system prompts, tools, guardrails | None                |
| Passive      | Git history          | Leaked secrets from old commits               | None                |
| Low-interact | JS source analysis   | API endpoints                                 | Very low            |
| Low-interact | 401 vs 404 enum      | API surface map                               | Low                 |
| Active       | Metadata leak        | Model identity without asking                 | Low                 |
| Active       | Contradiction test   | Model identity through correction             | Medium              |
| Active       | Knowledge cutoff     | Model family/version                          | Medium              |
| Active       | Behavioral analysis  | Model family                                  | Medium              |
| Active       | RAG document probing | Internal docs, hostnames, creds               | High (space it out) |

Next up: we use all this intel to actually attack these systems. Prompt injection, memory poisoning, RAG injection, tool hijacking all of that is built on what we gathered here.

***
