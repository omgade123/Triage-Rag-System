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

  // Embedding model
  embeddingModel: "text-embedding-3-small" as const,
  embeddingDimensions: 1536,
};
