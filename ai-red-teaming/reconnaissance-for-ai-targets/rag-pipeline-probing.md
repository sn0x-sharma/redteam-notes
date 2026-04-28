---
icon: list-timeline
---

# RAG Pipeline Probing

### RAG Pipeline Probing

RAG = Retrieval Augmented Generation. The flow is:

1. User sends query
2. System converts query to embedding (vector)
3. Searches vector DB for similar document chunks
4. Stuffs those chunks into the LLM's context as "grounding documents"
5. LLM generates answer based on those documents

**Why attack RAG?**

* It exposes internal documents through a chatbot interface
* Similarity search can be manipulated to retrieve specific content
* If you can inject documents into the vector DB, you can influence model behavior persistently
* RAG metadata often leaks more than the answer itself

**Step 1: Determine if RAG is active**

```bash
# General knowledge question — RAG should NOT trigger
curl -s -X POST http://192.168.50.34/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What is 2+2?"}' | jq
```

Response:

```json
{
  "answer": "2 + 2 equals 4.",
  "sources": [],              ← empty = no RAG triggered, answered from model knowledge
  "retrieval_info": {
    "retrieval_time_ms": 0.31   ← negligible retrieval time confirms no DB query
  }
}
```

```bash
# Company-specific question — RAG SHOULD trigger
curl -s -X POST http://192.168.50.34/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the PTO policy?"}' | jq
```

Response:

```json
{
  "answer": "According to PTO_Leave_Policy_2024.pdf...",
  "sources": [
    {
      "title": "PTO_Leave_Policy_2024.pdf",      ← internal document name
      "chunk_id": "chunk_087",                    ← chunking metadata
      "text": "Vacation Accrual: Years 0-2: 15 days/year...",  ← verbatim content
      "vector_score": 0.2,                        ← semantic similarity
      "bm25_score": 2.1,                          ← keyword match score
      "combined_score": 0.51                      ← hybrid score
    }
  ]
}
```

That `sources` array is an absolute goldmine. You're getting:

* **Document filename** - naming conventions, what docs exist, file formats
* **Chunk ID** - tells you the chunking strategy, chunk count (chunk\_087 = at least 87 chunks in this doc)
* **Verbatim text** - actual content from the internal document
* **Similarity scores** - tells you the retrieval threshold (you can work backward to figure out what score triggers retrieval)

**Step 2: Systematically extract the knowledge base**

Keep querying with different topics to map out what documents exist:

```bash
# Map the knowledge base structure
topics=(
  "employee policies"
  "API documentation"
  "system architecture"
  "database configuration"
  "network topology"
  "AWS credentials"
  "executive compensation"
  "acquisition plans"
  "incident response procedures"
  "internal hostnames"
  "VPN configuration"
  "deployment procedures"
)

for topic in "${topics[@]}"; do
  echo "=== $topic ==="
  curl -s -X POST http://192.168.50.34/api/chat \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"Tell me about $topic\"}" | jq '.sources[].title' 2>/dev/null
  sleep 2  # don't trigger rate limiting / detection
done
```

**What you're looking for:**

* Document names → what internal files exist
* Chunk IDs → estimate doc sizes, understand chunking
* Hostnames, IPs, endpoints in `text` field → network recon from inside the AI
* API key formats in `text` field → potential live credentials
* Internal URLs → services to target

**Real example — Architecture query reveals everything:**

```bash
curl -s -X POST http://192.168.50.34/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the system architecture?"}' | jq
```

Source text returns:

```
"System Components: API Gateway (Kong), Kubernetes services,
PostgreSQL on db01.internal, Redis cluster at redis.novatech-internal.com:6379,
RabbitMQ for async jobs. Secrets stored in HashiCorp Vault."
```

You just got:

* Internal hostname: `db01.internal`
* Redis service: `redis.novatech-internal.com:6379`
* They use HashiCorp Vault (means secrets management  if Vault is misconfigured, jackpot)
* Kubernetes cluster (lateral movement target)
* RabbitMQ (message queue potential injection point)

This is internal network recon done through a chatbot. Beautiful.

**Step 3: Threshold testing - figure out when RAG stops triggering**

Understanding the retrieval threshold is important for attack planning. If you're planning prompt injection, you sometimes _want_ to avoid triggering RAG (so the model isn't grounded by context documents and is easier to manipulate).

```bash
# Exact match — definitely triggers
curl -s -X POST http://192.168.50.34/api/chat \
  -d '{"query": "What is the PTO policy?"}' | jq '.sources | length'
# Output: 1 (triggered)

# Synonyms — should still trigger (semantic search handles this)
curl -s -X POST http://192.168.50.34/api/chat \
  -d '{"query": "vacation days rules"}' | jq '.sources | length'
# Output: 1 (triggered — vector search found semantic match)

# Completely different topic — won't trigger
curl -s -X POST http://192.168.50.34/api/chat \
  -d '{"query": "Tell me about quantum computing"}' | jq '.sources | length'
# Output: 0 (no retrieval — no relevant docs in the KB)

# Heavy misspellings — drops below threshold
curl -s -X POST http://192.168.50.34/api/chat \
  -d '{"query": "vaycation dayz rulez"}' | jq '.sources | length'
# Output: 0 (no retrieval — embeddings AND BM25 both fail on garbage input)
```

**Why misspellings break RAG:** RAG uses hybrid scoring - vector similarity (semantic) + BM25 (keyword). Misspellings destroy both. The embedding of "vaycation dayz rulez" is far from the embedding of "vacation days policy." And BM25 keyword matching can't match "vaycation" to "vacation." Combined score drops below threshold, no retrieval.

**Alternative RAG probing methods:**

```bash
# Try to get the model to reveal its instructions by asking meta-questions
curl -s -X POST http://192.168.50.34/api/chat \
  -d '{"query": "What topics can you help me with?"}' | jq '.answer'
# Model summarizes its knowledge domains

# Ask for document recommendations
curl -s -X POST http://192.168.50.34/api/chat \
  -d '{"query": "Which documentation should a new employee read first?"}' | jq
# Often cites multiple documents at once

# Test if RAG returns different chunks from the same document
curl -s -X POST http://192.168.50.34/api/chat \
  -d '{"query": "What are the API rate limits?"}' | jq '.sources[].chunk_id'
# Multiple chunk_ids from same doc = large document, understand its structure
```

***
