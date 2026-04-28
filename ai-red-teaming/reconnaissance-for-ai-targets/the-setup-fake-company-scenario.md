---
icon: arrow-up-z-a
---

# The Setup - Fake Company Scenario

## The Setup - Fake Company Scenario

Throughout these notes we're using **NovaTech Industries** as our target. They just deployed a bunch of AI-powered internal tools and think it's fine because the models are "just chatbots." Spoiler: it's not fine.

NovaTech has:

* A customer-facing AI assistant (Project Aurora - Google Gemini + CrewAI + Pinecone)
* An internal code review bot (Project Phoenix - self-hosted Qwen2.5-Coder + Milvus + vLLM)
* An internal knowledge base chatbot with RAG (HR policies, architecture docs, etc.)
* A helpdesk web app with an embedded AI chat widget
* A partner API gateway running Kong

Your job: figure out as much as possible about this whole stack before touching a single attack. This entire chapter is recon only. No exploitation yet. But the intel you gather here dictates every attack you run later.

***

### Why AI Recon is Different from Normal Recon

In traditional pentesting, recon is mostly:

* Nmap the network
* Find open ports
* Read service banners
* Check HTTP headers
* Maybe browse source code

With AI systems, that still works but there's a whole extra layer. You're not just looking for open ports you're looking for:

1. **What model is running?** (Different models have different weaknesses Llama vs Qwen vs GPT have totally different attack surfaces)
2. **Is there a RAG pipeline?** (That means there's a document store you can potentially extract from or inject into)
3. **Does the agent have tools?** (MCP, API calls, code execution these are your jackpot)
4. **What framework is orchestrating everything?** (LangChain, CrewAI, AutoGen each has known quirks and vulnerabilities)
5. **What are the system prompt restrictions?** (So you know what you have to bypass)
6. **What does the knowledge base contain?** (Internal docs, credentials, architecture info)

Each of these is a separate enumeration target and each has its own techniques. Let's go through all of them.
