# Triage RAG System — Project Context

## What this is
A RAG-based vulnerability report triage system. Given an incoming
vulnerability report (title + description), it finds semantically similar
historical reports, flags likely duplicates, and predicts a classification
(CWE category) and severity — with every prediction traceable back to the
specific historical report it was grounded in.

This is a portfolio project built to demonstrate RAG/retrieval system design
skills for AI backend engineering roles, particularly in the security domain.

## Why this design
- Vulnerability report triage is a harder RAG problem than typical "chat
  with your docs" — it needs duplicate detection (not just Q&A), structured
  metadata alongside semantic search, and grounded, cited outputs since
  security analysts need to trust and verify AI-suggested classifications.
- The architecture deliberately separates ingestion (async, queued) from
  retrieval (synchronous, request-time) so each can be scaled/debugged
  independently.

## Tech stack
- **Language/runtime:** TypeScript, Node.js
- **API layer:** Express
- **Database:** PostgreSQL with the `pgvector` extension for vector storage
  and similarity search (HNSW index)
- **Queue:** BullMQ + Redis for async ingestion (fetch → embed → store)
- **Embeddings:** OpenAI `text-embedding-3-small` (1536 dimensions)
- **Validation:** zod for request schema validation
- **Containerization:** Docker Compose for local Postgres + Redis

## Data source
NVD (National Vulnerability Database) public CVE feed:
`https://services.nvd.nist.gov/rest/json/cves/2.0`
- No auth required for basic rate limits (5 req/30s); optional API key raises
  this to 50 req/30s.
- Each CVE record provides: id, description, CWE (weakness type), CVSS
  severity score/rating, published date.

## Data model (Postgres table: `vulnerability_reports`)
- `id` (text, PK) — e.g. CVE-2024-XXXXX
- `title`, `description` (text)
- `cwe` (text) — vulnerability category, e.g. "CWE-79"
- `severity` (text) — LOW / MEDIUM / HIGH / CRITICAL
- `cvss_score` (real)
- `published_at` (timestamptz)
- `source` (text) — data provenance, e.g. "nvd"
- `embedding` (vector(1536)) — pgvector column, HNSW-indexed with cosine ops
- Additional indexes on `cwe` and `severity` for metadata-filtered retrieval,
  plus a GIN full-text index on `description` for future BM25/hybrid search.

## Pipeline stages
1. **Fetch** — pull CVE records from NVD API, paginated.
2. **Queue** — push each fetched report onto a BullMQ ingestion queue
   (decouples slow/rate-limited fetching from embedding work).
3. **Embed** — worker consumes queue, embeds `title + cwe + description`
   concatenated as one string (structured fields folded into the embedded
   text so semantic search picks up on category signal, not just prose).
4. **Store** — upsert into `vulnerability_reports` with the embedding vector.
5. **Retrieve** (request-time) — given an incoming report's text, embed it
   and run cosine similarity search against stored reports, optionally
   filtered by CWE.
6. **Duplicate check** — if the top similarity match exceeds a threshold
   (currently 0.92, needs tuning against a labeled eval set), flag as likely
   duplicate.
7. **Classify** (not yet built) — LLM layer predicts CWE/severity for the
   incoming report, using retrieved similar reports as grounding context.

## API surface
- `POST /triage/check` — body `{ title, description }` → returns
  `{ isDuplicate, topMatch, candidates }`, each candidate with a similarity
  score and traceable source id.
- `GET /triage/similar?q=...&cwe=CWE-79` — semantic search, optionally
  scoped to a CWE category.

## Roadmap / not yet built
- **MMR (Maximal Marginal Relevance) re-ranking** — current retrieval is
  plain top-k cosine similarity, which can return near-duplicate results
  that don't add signal. MMR re-ranks for relevance + diversity.
- **BM25 + vector hybrid scoring** — CVE text has exact-match terms (CVE
  IDs, product/vendor names, CWE codes) where pure semantic search
  underperforms keyword search. Postgres full-text search (`tsvector`,
  already indexed) should be combined with vector similarity.
- **LLM classification layer** — predict CWE/severity for an incoming
  report, grounded in the retrieved similar reports as few-shot context,
  with citations back to which report supported which part of the
  classification.
- **Evaluation harness** — precision@k / recall@k measured against the real
  CVSS/CWE labels already present in the NVD data (a built-in ground truth,
  since we're not hand-labeling). This is what turns "I built a triage
  system" into "I built a triage system and measured it."

## Working style / constraints for this session
- The person building this (Om) wants to write the implementation code
  himself — the agent should explain concepts, suggest approaches, and
  review code for bugs/improvements, but should let him write the actual
  logic rather than generating full solutions unprompted.
- Prioritize correctness and explainability over cleverness — every
  retrieval/classification decision should be traceable to its source data,
  since that's the core design principle of the whole project.
