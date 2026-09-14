import dotenv from "dotenv";
dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || "3000", 10),
  databaseUrl: process.env.DATABASE_URL!,
  redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
  openaiApiKey: process.env.OPENAI_API_KEY!,
  nvdApiKey: process.env.NVD_API_KEY || "",

  // Retrieval tuning
  duplicateThreshold: 0.92,
  defaultTopK: 5,

  // Size of the candidate pool fetched before re-ranking (MMR / hybrid
  // fusion). Larger pool = more to diversify/fuse over, at more DB cost.
  retrievalPoolSize: 20,

  // MMR (Maximal Marginal Relevance) trade-off. 1.0 = pure relevance,
  // 0.0 = pure diversity. 0.7 leans toward relevance while pruning
  // near-duplicate results that add no new signal.
  mmrLambda: 0.7,

  // Reciprocal Rank Fusion constant for hybrid (vector + BM25) search.
  // Standard default from the RRF paper.
  rrfK: 60,

  // Embedding model
  embeddingModel: "text-embedding-3-small" as const,
  embeddingDimensions: 1536,

  // Classification (generation) model — the LLM that predicts CWE/severity
  // grounded in retrieved similar reports.
  classificationModel: "gpt-4o-mini" as const,
};
