import { pool } from "../db/pool";
import pgvector from "pgvector";
import { config } from "../config";

export interface SimilarReport {
  id: string;
  title: string;
  description: string;
  cwe: string | null;
  severity: string | null;
  cvssScore: number | null;
  publishedAt: string | null;
  similarity: number;
}

// A candidate that also carries its stored embedding vector, so re-rankers
// (e.g. MMR) can compute candidate-to-candidate similarity.
export interface ScoredCandidate extends SimilarReport {
  embedding: number[];
}

/**
 * Finds the top-k most similar reports to a query embedding using
 * cosine similarity via pgvector's <=> operator.
 *
 * Optionally filters by CWE category for scoped search.
 */
export async function findSimilar(
  queryEmbedding: number[],
  topK: number = config.defaultTopK,
  cweFilter?: string
): Promise<SimilarReport[]> {
  const vectorSql = pgvector.toSql(queryEmbedding);

  let query: string;
  let params: unknown[];

  if (cweFilter) {
    query = `
      SELECT
        id, title, description, cwe, severity, cvss_score, published_at,
        1 - (embedding <=> $1::vector) AS similarity
      FROM vulnerability_reports
      WHERE cwe = $2
      ORDER BY embedding <=> $1::vector
      LIMIT $3
    `;
    params = [vectorSql, cweFilter, topK];
  } else {
    query = `
      SELECT
        id, title, description, cwe, severity, cvss_score, published_at,
        1 - (embedding <=> $1::vector) AS similarity
      FROM vulnerability_reports
      ORDER BY embedding <=> $1::vector
      LIMIT $2
    `;
    params = [vectorSql, topK];
  }

  const result = await pool.query(query, params);

  return result.rows.map((row) => ({
    id: row.id,
    title: row.title,
    description: row.description,
    cwe: row.cwe,
    severity: row.severity,
    cvssScore: row.cvss_score,
    publishedAt: row.published_at,
    similarity: parseFloat(row.similarity),
  }));
}

/**
 * Fetches a larger candidate pool (with each row's stored embedding vector)
 * for re-ranking. The pool is ordered by cosine similarity like `findSimilar`,
 * but returns `poolSize` rows and includes the embedding so an MMR re-ranker
 * can measure diversity between candidates.
 */
export async function findVectorPool(
  queryEmbedding: number[],
  poolSize: number = config.retrievalPoolSize,
  cweFilter?: string
): Promise<ScoredCandidate[]> {
  const vectorSql = pgvector.toSql(queryEmbedding);

  let query: string;
  let params: unknown[];

  if (cweFilter) {
    query = `
      SELECT
        id, title, description, cwe, severity, cvss_score, published_at,
        embedding::text AS embedding_text,
        1 - (embedding <=> $1::vector) AS similarity
      FROM vulnerability_reports
      WHERE cwe = $2
      ORDER BY embedding <=> $1::vector
      LIMIT $3
    `;
    params = [vectorSql, cweFilter, poolSize];
  } else {
    query = `
      SELECT
        id, title, description, cwe, severity, cvss_score, published_at,
        embedding::text AS embedding_text,
        1 - (embedding <=> $1::vector) AS similarity
      FROM vulnerability_reports
      ORDER BY embedding <=> $1::vector
      LIMIT $2
    `;
    params = [vectorSql, poolSize];
  }

  const result = await pool.query(query, params);

  return result.rows.map((row) => ({
    id: row.id,
    title: row.title,
    description: row.description,
    cwe: row.cwe,
    severity: row.severity,
    cvssScore: row.cvss_score,
    publishedAt: row.published_at,
    similarity: parseFloat(row.similarity),
    embedding: (pgvector.fromSql(row.embedding_text) as number[]) ?? [],
  }));
}
