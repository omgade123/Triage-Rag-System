import { pool } from "../db/pool";

/**
 * Retrieval evaluation harness.
 *
 * Turns "I built a triage system" into "I built one and measured it." The NVD
 * data ships its own ground truth: each report's CWE label. So we can measure
 * retrieval quality without hand-labeling — a good neighbor is one that shares
 * the query report's CWE.
 *
 * Method (leave-one-out over a random sample):
 *   1. Sample N reports that have a CWE label.
 *   2. For each, use its OWN stored embedding as the query (so we measure the
 *      retrieval index, not the embedding API) and fetch the top-k nearest
 *      neighbors, excluding itself.
 *   3. A neighbor is "relevant" iff it shares the query's CWE.
 *
 * Metrics (macro-averaged over the sample):
 *   - precision@k : relevant neighbors / k
 *   - recall@k    : relevant neighbors / total other reports with that CWE
 *   - hit-rate@k  : fraction of queries with >=1 relevant neighbor in top-k
 *   - MRR         : mean reciprocal rank of the first relevant neighbor
 *
 * Usage: npm run eval [k] [sampleSize]
 * Example: npm run eval 5 100
 */

interface Sample {
  id: string;
  cwe: string;
  embeddingText: string;
}

async function evaluate(): Promise<void> {
  const k = parseInt(process.argv[2] || "5", 10);
  const sampleSize = parseInt(process.argv[3] || "100", 10);

  console.log(`Evaluating retrieval: k=${k}, sampleSize=${sampleSize}\n`);

  // Total reports per CWE — the denominator for recall.
  const cweCountsRes = await pool.query<{ cwe: string; count: string }>(
    `SELECT cwe, COUNT(*)::text AS count
       FROM vulnerability_reports
      WHERE cwe IS NOT NULL
      GROUP BY cwe`
  );
  const cweCounts = new Map<string, number>();
  for (const row of cweCountsRes.rows) {
    cweCounts.set(row.cwe, parseInt(row.count, 10));
  }

  // Random sample of labeled reports to use as queries.
  const sampleRes = await pool.query<Sample>(
    `SELECT id, cwe, embedding::text AS "embeddingText"
       FROM vulnerability_reports
      WHERE cwe IS NOT NULL AND embedding IS NOT NULL
      ORDER BY random()
      LIMIT $1`,
    [sampleSize]
  );
  const samples = sampleRes.rows;

  if (samples.length === 0) {
    console.error(
      "No labeled reports found. Seed the database first (npm run seed)."
    );
    await pool.end();
    process.exit(1);
  }

  let sumPrecision = 0;
  let sumRecall = 0;
  let recallCount = 0; // queries where recall is defined (relevantTotal > 0)
  let hits = 0;
  let sumReciprocalRank = 0;

  for (const sample of samples) {
    // Nearest neighbors by cosine distance, excluding the query itself.
    const neighborsRes = await pool.query<{ cwe: string | null }>(
      `SELECT cwe
         FROM vulnerability_reports
        WHERE id <> $2 AND embedding IS NOT NULL
        ORDER BY embedding <=> $1::vector
        LIMIT $3`,
      [sample.embeddingText, sample.id, k]
    );
    const neighbors = neighborsRes.rows;

    const relevantRetrieved = neighbors.filter(
      (n) => n.cwe === sample.cwe
    ).length;

    // precision@k
    sumPrecision += relevantRetrieved / k;

    // recall@k — denominator is other reports sharing this CWE.
    const relevantTotal = (cweCounts.get(sample.cwe) ?? 1) - 1;
    if (relevantTotal > 0) {
      sumRecall += relevantRetrieved / relevantTotal;
      recallCount += 1;
    }

    // hit-rate & MRR
    const firstRelevantIdx = neighbors.findIndex((n) => n.cwe === sample.cwe);
    if (firstRelevantIdx !== -1) {
      hits += 1;
      sumReciprocalRank += 1 / (firstRelevantIdx + 1);
    }
  }

  const n = samples.length;
  const pct = (x: number) => (x * 100).toFixed(1) + "%";

  console.log("=".repeat(44));
  console.log(`Queries evaluated : ${n}`);
  console.log(`precision@${k}       : ${pct(sumPrecision / n)}`);
  console.log(
    `recall@${k}          : ${
      recallCount > 0 ? pct(sumRecall / recallCount) : "n/a"
    }  (over ${recallCount} queries with >1 same-CWE report)`
  );
  console.log(`hit-rate@${k}        : ${pct(hits / n)}`);
  console.log(`MRR               : ${(sumReciprocalRank / n).toFixed(3)}`);
  console.log("=".repeat(44));

  await pool.end();
  process.exit(0);
}

evaluate().catch(async (err) => {
  console.error("Evaluation failed:", err);
  await pool.end().catch(() => {});
  process.exit(1);
});
