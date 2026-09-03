import { Router, Request, Response } from "express";
import { z } from "zod";
import { embedText, buildEmbeddingInput } from "../embedding/embedder";
import { findSimilar } from "../retrieval/search";
import { checkDuplicate } from "../retrieval/duplicate";
import { config } from "../config";

export const triageRouter = Router();

// --- Request validation schemas ---

const triageCheckSchema = z.object({
  title: z.string().min(1, "title is required"),
  description: z.string().min(1, "description is required"),
});

const similarQuerySchema = z.object({
  q: z.string().min(1, "query string 'q' is required"),
  cwe: z.string().optional(),
  topK: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : config.defaultTopK)),
});

// --- POST /triage/check ---
// Body: { title, description }
// Returns: { isDuplicate, topMatch, candidates }

triageRouter.post("/check", async (req: Request, res: Response) => {
  try {
    const parsed = triageCheckSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const { title, description } = parsed.data;

    // Embed the incoming report using the same format as stored reports
    const text = buildEmbeddingInput(title, null, description);
    const queryEmbedding = await embedText(text);

    // Find similar reports
    const candidates = await findSimilar(queryEmbedding);

    // Check for duplicates
    const result = checkDuplicate(candidates);

    res.json(result);
  } catch (err) {
    console.error("Error in POST /triage/check:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- GET /triage/similar?q=...&cwe=CWE-79&topK=10 ---
// Semantic search, optionally scoped to a CWE category

triageRouter.get("/similar", async (req: Request, res: Response) => {
  try {
    const parsed = similarQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const { q, cwe, topK } = parsed.data;

    // Embed the search query
    const queryEmbedding = await embedText(q);

    // Run similarity search with optional CWE filter
    const results = await findSimilar(queryEmbedding, topK, cwe);

    res.json({ query: q, cwe: cwe || null, results });
  } catch (err) {
    console.error("Error in GET /triage/similar:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
