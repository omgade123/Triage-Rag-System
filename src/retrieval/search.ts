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
