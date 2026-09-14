import { pool } from "../db/pool";
import pgvector from "pgvector";
import { config } from "../config";
import { SimilarReport } from "./search";

export interface HybridResult extends SimilarReport {
  // Fused Reciprocal Rank Fusion score (higher = better).
  fusedScore: number;
  // 1-based rank in each modality, or null if the doc didn't appear there.
  vectorRank: number | null;
  textRank: number | null;
}

/**
 * Hybrid retrieval combining semantic (vector) similarity and lexical (BM25-
 * style Postgres full-text) search via Reciprocal Rank Fusion.
 *
 * CVE text has exact-match terms — CVE IDs, product/vendor names, CWE codes —
 * where pure semantic search underperforms keyword search, and vice-versa.
 * RRF fuses the two rankings without needing to normalize their (very
 * different) score scales:
 *
 *     score(doc) = Σ 1 / (rrfK + rank_in_modality)
 *
 * The fusion runs in a single SQL statement: each modality contributes a
 * top-`poolSize` ranked list, they're FULL OUTER JOINed on id, and the final
 * projection recomputes cosine similarity for every fused doc so the reported
 * `similarity` is always accurate (not just for docs the vector arm surfaced).
 */
export async function hybridSearch(
  queryEmbedding: number[],
  queryText: string,
  topK: number = config.defaultTopK,
  cweFilter?: string
): Promise<HybridResult[]> {
  const vectorSql = pgvector.toSql(queryEmbedding);

  // $1 vector, $2 text, $3 rrfK, $4 poolSize, $5 topK, [$6 cwe]
  const cweClause = cweFilter ? "AND cwe = $6" : "";

  const query = `
    WITH vector_matches AS (
      SELECT id,
             row_number() OVER (ORDER BY embedding <=> $1::vector) AS vrank
      FROM vulnerability_reports
      WHERE embedding IS NOT NULL ${cweClause}
      ORDER BY embedding <=> $1::vector
      LIMIT $4
    ),
    text_matches AS (
      SELECT id,
             row_number() OVER (
               ORDER BY ts_rank(
                 to_tsvector('english', description),
                 plainto_tsquery('english', $2)
               ) DESC
             ) AS trank
      FROM vulnerability_reports
      WHERE to_tsvector('english', description) @@ plainto_tsquery('english', $2)
        ${cweClause}
      ORDER BY ts_rank(
        to_tsvector('english', description),
        plainto_tsquery('english', $2)
      ) DESC
      LIMIT $4
    ),
    fused AS (
      SELECT COALESCE(v.id, t.id) AS id,
             v.vrank,
             t.trank,
             COALESCE(1.0 / ($3 + v.vrank), 0)
               + COALESCE(1.0 / ($3 + t.trank), 0) AS fused_score
      FROM vector_matches v
      FULL OUTER JOIN text_matches t ON v.id = t.id
    )
    SELECT r.id, r.title, r.description, r.cwe, r.severity, r.cvss_score,
           r.published_at,
           1 - (r.embedding <=> $1::vector) AS similarity,
           f.fused_score, f.vrank, f.trank
    FROM fused f
    JOIN vulnerability_reports r ON r.id = f.id
    ORDER BY f.fused_score DESC
    LIMIT $5
  `;

  const params: unknown[] = [
    vectorSql,
    queryText,
    config.rrfK,
    config.retrievalPoolSize,
    topK,
  ];
  if (cweFilter) params.push(cweFilter);

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
    fusedScore: parseFloat(row.fused_score),
    vectorRank: row.vrank !== null ? Number(row.vrank) : null,
    textRank: row.trank !== null ? Number(row.trank) : null,
  }));
}
