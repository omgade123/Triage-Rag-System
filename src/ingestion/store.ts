import { pool } from "../db/pool";
import { FetchedReport } from "./fetcher";
import pgvector from "pgvector";

/**
 * Upserts a vulnerability report with its embedding vector into Postgres.
 * ON CONFLICT updates all fields so re-ingestion refreshes stale data.
 */
export async function upsertReport(
  report: FetchedReport,
  embedding: number[]
): Promise<void> {
  const vectorSql = pgvector.toSql(embedding);

  await pool.query(
    `INSERT INTO vulnerability_reports
       (id, title, description, cwe, severity, cvss_score, published_at, source, embedding)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'nvd', $8)
     ON CONFLICT (id) DO UPDATE SET
       title = EXCLUDED.title,
       description = EXCLUDED.description,
       cwe = EXCLUDED.cwe,
       severity = EXCLUDED.severity,
       cvss_score = EXCLUDED.cvss_score,
       published_at = EXCLUDED.published_at,
       embedding = EXCLUDED.embedding`,
    [
      report.id,
      report.title,
      report.description,
      report.cwe,
      report.severity,
      report.cvssScore,
      report.publishedAt,
      vectorSql,
    ]
  );
}
