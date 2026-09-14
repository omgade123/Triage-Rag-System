import OpenAI from "openai";
import { z } from "zod";
import { config } from "../config";
import { SimilarReport } from "../retrieval/search";

const openai = new OpenAI({ apiKey: config.openaiApiKey });

/**
 * The structured prediction returned by the classification layer.
 * Every field is grounded in the retrieved similar reports, and `citations`
 * traces which historical report(s) supported the prediction — the core
 * design principle of the project: no prediction without provenance.
 */
export interface Classification {
  predictedCwe: string | null;
  predictedSeverity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null;
  confidence: "low" | "medium" | "high";
  rationale: string;
  citations: Array<{ reportId: string; reason: string }>;
}

// zod schema to validate the LLM's JSON output before we trust it.
const classificationSchema = z.object({
  predictedCwe: z.string().nullable(),
  predictedSeverity: z
    .enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    .nullable(),
  confidence: z.enum(["low", "medium", "high"]),
  rationale: z.string(),
  citations: z.array(
    z.object({
      reportId: z.string(),
      reason: z.string(),
    })
  ),
});

const SYSTEM_PROMPT = `You are a security triage assistant. Your job is to classify an incoming \
vulnerability report by predicting its CWE (weakness category) and CVSS severity.

You are given a set of historical vulnerability reports retrieved by semantic \
similarity to the incoming report. These are your ONLY source of grounding.

Rules:
- Base your prediction ONLY on the retrieved reports provided. Do not invent \
CWE codes or severities from outside knowledge.
- Every prediction MUST cite the specific retrieved report id(s) that support \
it. If nothing in the retrieved set supports a confident prediction, set the \
field to null and lower your confidence.
- Prefer the CWE/severity that appears most consistently across the most \
similar retrieved reports.
- Keep the rationale concise (2-4 sentences) and explain which retrieved \
reports drove the decision.

Respond with ONLY a JSON object matching this shape:
{
  "predictedCwe": string | null,        // e.g. "CWE-79", or null if unclear
  "predictedSeverity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null,
  "confidence": "low" | "medium" | "high",
  "rationale": string,
  "citations": [{ "reportId": string, "reason": string }]
}`;

/**
 * Builds the grounding context block from retrieved similar reports.
 */
function buildContext(candidates: SimilarReport[]): string {
  if (candidates.length === 0) {
    return "(no similar historical reports were retrieved)";
  }

  return candidates
    .map((c, i) => {
      const sim = (c.similarity * 100).toFixed(1);
      return [
        `[${i + 1}] id=${c.id} (similarity ${sim}%)`,
        `    cwe: ${c.cwe ?? "unknown"}`,
        `    severity: ${c.severity ?? "unknown"}` +
          (c.cvssScore != null ? ` (cvss ${c.cvssScore})` : ""),
        `    description: ${c.description.slice(0, 500)}`,
      ].join("\n");
    })
    .join("\n\n");
}

/**
 * Predicts CWE + severity for an incoming report, grounded in the retrieved
 * similar reports. Returns a structured, cited classification.
 *
 * If the LLM output can't be parsed/validated, returns a safe low-confidence
 * result rather than throwing — triage should degrade gracefully.
 */
export async function classifyReport(
  title: string,
  description: string,
  candidates: SimilarReport[]
): Promise<Classification> {
  const userPrompt = [
    "INCOMING REPORT",
    `title: ${title}`,
    `description: ${description}`,
    "",
    "RETRIEVED SIMILAR REPORTS (your grounding context):",
    buildContext(candidates),
  ].join("\n");

  const response = await openai.chat.completions.create({
    model: config.classificationModel,
    temperature: 0,
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: userPrompt },
    ],
  });

  const raw = response.choices[0]?.message?.content ?? "";

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return degraded("Model returned unparseable output.");
  }

  const validated = classificationSchema.safeParse(parsed);
  if (!validated.success) {
    return degraded("Model output failed schema validation.");
  }

  // Guard against hallucinated citations: keep only ids that were actually
  // in the retrieved set, so every citation is verifiable.
  const validIds = new Set(candidates.map((c) => c.id));
  const citations = validated.data.citations.filter((cite) =>
    validIds.has(cite.reportId)
  );

  return { ...validated.data, citations };
}

function degraded(rationale: string): Classification {
  return {
    predictedCwe: null,
    predictedSeverity: null,
    confidence: "low",
    rationale,
    citations: [],
  };
}
