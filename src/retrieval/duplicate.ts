import { config } from "../config";
import { SimilarReport } from "./search";

export interface DuplicateCheckResult {
  isDuplicate: boolean;
  topMatch: SimilarReport | null;
  candidates: SimilarReport[];
}

/**
 * Checks if the top similarity match exceeds the duplicate threshold.
 * Returns the full candidate list for transparency — every prediction is
 * traceable back to its source report.
 */
export function checkDuplicate(
  candidates: SimilarReport[]
): DuplicateCheckResult {
  if (candidates.length === 0) {
    return { isDuplicate: false, topMatch: null, candidates: [] };
  }

  const topMatch = candidates[0];
  const isDuplicate = topMatch.similarity >= config.duplicateThreshold;

  return {
    isDuplicate,
    topMatch,
    candidates,
  };
}
