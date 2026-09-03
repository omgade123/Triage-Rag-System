import { Worker, Job } from "bullmq";
import IORedis from "ioredis";
import { config } from "../config";
import { FetchedReport } from "./fetcher";
import { embedText, buildEmbeddingInput } from "../embedding/embedder";
import { upsertReport } from "./store";

const connection = new IORedis(config.redisUrl, { maxRetriesPerRequest: null });

/**
 * BullMQ worker that consumes from the ingestion queue.
 * For each report: embeds title+CWE+description, then upserts into Postgres.
 */
export function startWorker(): Worker<FetchedReport> {
  const worker = new Worker<FetchedReport>(
    "ingestion",
    async (job: Job<FetchedReport>) => {
      const report = job.data;
      console.log(`Processing: ${report.id}`);

      // Build embedding input: title + CWE + description
      const text = buildEmbeddingInput(
        report.title,
        report.cwe,
        report.description
      );

      // Generate embedding via OpenAI
      const embedding = await embedText(text);

      // Upsert into Postgres with the embedding vector
      await upsertReport(report, embedding);

      console.log(`Stored: ${report.id}`);
    },
    {
      connection,
      concurrency: 5, // Process 5 jobs in parallel
      limiter: {
        max: 10,
        duration: 1000, // Max 10 embedding calls per second
      },
    }
  );

  worker.on("completed", (job) => {
    console.log(`Job ${job.id} completed`);
  });

  worker.on("failed", (job, err) => {
    console.error(`Job ${job?.id} failed:`, err.message);
  });

  return worker;
}
