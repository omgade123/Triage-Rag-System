import { config } from "../config";
import { ScoredCandidate, SimilarReport } from "./search";

/**
 * Cosine similarity between two equal-length vectors.
 * Returns 0 for degenerate (zero-magnitude or mismatched) inputs.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length === 0 || a.length !== b.length) return 0;

  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

/**
 * Maximal Marginal Relevance re-ranking.
 *
 * Plain top-k cosine search can return several near-identical reports that add
 * no new signal. MMR greedily selects the candidate that maximizes:
 *
 *     lambda * sim(query, candidate)
 *   - (1 - lambda) * max sim(candidate, already-selected)
 *
 * so each pick is both relevant to the query and different from what's already
 * chosen. The first pick is always the highest query-similarity candidate
 * (the selected set is empty), which keeps the top match — and therefore the
 * duplicate check that reads it — identical to plain cosine search.
 *
 * The returned `similarity` field stays the candidate's cosine similarity to
 * the query (not the MMR objective), so downstream thresholds are unaffected.
 */
export function mmrRerank(
  queryEmbedding: number[],
  pool: ScoredCandidate[],
  k: number = config.defaultTopK,
  lambda: number = config.mmrLambda
): SimilarReport[] {
  const selected: ScoredCandidate[] = [];
  const remaining = [...pool];
  const limit = Math.min(k, pool.length);

  while (selected.length < limit && remaining.length > 0) {
    let bestIdx = 0;
    let bestScore = -Infinity;

    for (let i = 0; i < remaining.length; i++) {
      const cand = remaining[i];
      const relevance = cosineSimilarity(queryEmbedding, cand.embedding);

      let maxSimToSelected = 0;
      for (const sel of selected) {
        const sim = cosineSimilarity(cand.embedding, sel.embedding);
        if (sim > maxSimToSelected) maxSimToSelected = sim;
      }

      const mmrScore =
        lambda * relevance - (1 - lambda) * maxSimToSelected;

      if (mmrScore > bestScore) {
        bestScore = mmrScore;
        bestIdx = i;
      }
    }

    selected.push(remaining.splice(bestIdx, 1)[0]);
  }

  // Strip the embedding from the public result shape.
  return selected.map(({ embedding: _embedding, ...rest }) => rest);
}
