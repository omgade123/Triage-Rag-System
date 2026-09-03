import OpenAI from "openai";
import { config } from "../config";

const openai = new OpenAI({ apiKey: config.openaiApiKey });

/**
 * Embeds a single text string using OpenAI text-embedding-3-small.
 * Returns a 1536-dimensional float array.
 */
export async function embedText(text: string): Promise<number[]> {
  const response = await openai.embeddings.create({
    model: config.embeddingModel,
    input: text,
  });

  return response.data[0].embedding;
}

/**
 * Builds the text string we embed for a vulnerability report.
 * Concatenates structured fields into the embedded text so semantic search
 * picks up on category signal, not just prose.
 */
export function buildEmbeddingInput(
  title: string,
  cwe: string | null,
  description: string
): string {
  const parts = [title];
  if (cwe) parts.push(cwe);
  parts.push(description);
  return parts.join(" ");
}
