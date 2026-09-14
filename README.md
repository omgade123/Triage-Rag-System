# Triage-Rag-System

A vulnerability triage and duplicate-detection system built around a
retrieval-augmented generation (RAG) approach. Given an incoming vulnerability
report, it finds semantically similar historical CVEs, flags likely
duplicates, and predicts a classification (CWE category + CVSS severity) —
with every prediction traceable back to the specific historical report it was
grounded in.

## Architecture

The system deliberately separates **ingestion** (async, queued) from
**retrieval** (synchronous, request-time) so each can be scaled and debugged
independently.

```
Ingestion (async):   NVD API → fetch → BullMQ queue → embed → store (pgvector)
Retrieval (request): report → embed → cosine search → duplicate check → classify (LLM)
```

- **Language/runtime:** TypeScript, Node.js
- **API layer:** Express (+ a static frontend served from `public/`)
- **Database:** PostgreSQL with `pgvector` (HNSW index, cosine ops)
- **Queue:** BullMQ + Redis for async ingestion
- **Embeddings:** OpenAI `text-embedding-3-small` (1536 dims)
- **Classification:** OpenAI `gpt-4o-mini`, grounded in retrieved reports
- **Validation:** zod
- **Infra:** Docker Compose for local Postgres + Redis

## Getting started

### 1. Prerequisites

- Node.js 18+
- Docker (for Postgres + Redis)
- An OpenAI API key

### 2. Configure

Create a `.env` file in the repo root:

```env
PORT=3000
DATABASE_URL=postgres://triage:triage_dev@localhost:5432/triage_rag
REDIS_URL=redis://localhost:6379
OPENAI_API_KEY=sk-...
# Optional — raises NVD rate limit from 5 to 50 req/30s
NVD_API_KEY=
```

### 3. Start infrastructure & install

```bash
docker compose up -d      # Postgres + Redis
npm install
```

### 4. Migrate & seed

```bash
npm run migrate           # create tables, extension, indexes
npm run seed 200          # fetch ~200 CVEs from NVD → queue → embed → store
```

> `npm run seed` enqueues reports; the ingestion worker (started by
> `npm run dev`) consumes the queue to embed and store them. Start the server
> first, or run seed and then the server to let the worker drain the queue.

### 5. Run

```bash
npm run dev               # runs migrations, starts worker + API on :3000
```

Then open **http://localhost:3000** for the web UI.

## Web UI

The frontend (`public/`) is a dependency-free single-page app served by
Express. Paste in a report title + description (there's a **Load sample**
button), and it runs the full pipeline, showing:

- a **duplicate banner** (top match + similarity),
- the **predicted CWE / severity / confidence** with a plain-language
  rationale and **citations** back to the specific historical reports that
  grounded the prediction,
- the ranked list of **similar historical reports** with similarity bars.

## API

### `POST /triage/classify`
Full RAG triage: retrieve → duplicate check → grounded classification.

```jsonc
// request
{ "title": "Stored XSS in comment field", "description": "…", "cwe": "CWE-79" }

// response
{
  "isDuplicate": false,
  "topMatch": { "id": "CVE-…", "similarity": 0.88, ... },
  "candidates": [ { "id": "CVE-…", "similarity": 0.88, "cwe": "CWE-79", ... } ],
  "classification": {
    "predictedCwe": "CWE-79",
    "predictedSeverity": "MEDIUM",
    "confidence": "high",
    "rationale": "…",
    "citations": [ { "reportId": "CVE-…", "reason": "…" } ]
  }
}
```

### `POST /triage/check`
Duplicate detection only. Body `{ title, description }` →
`{ isDuplicate, topMatch, candidates }`.

### `GET /triage/similar?q=...&cwe=CWE-79&topK=10`
Semantic search, optionally scoped to a CWE category.

### `GET /health`
Liveness check.

## Design principle

Correctness and explainability over cleverness — every retrieval and
classification decision is traceable to its source data. The classifier is
instructed to ground predictions **only** in the retrieved reports and to
cite them; citations to ids outside the retrieved set are filtered out
server-side so no prediction can reference a report that wasn't actually
surfaced.

## Roadmap / not yet built

- **MMR (Maximal Marginal Relevance) re-ranking** — diversify top-k results.
- **BM25 + vector hybrid scoring** — combine the existing `tsvector` full-text
  index with vector similarity for exact-match terms (CVE IDs, product names).
- **Evaluation harness** — precision@k / recall@k against the CWE/CVSS labels
  already present in the NVD data (built-in ground truth).
