---
icon: folder
---

# CHEATSHEET

```
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
