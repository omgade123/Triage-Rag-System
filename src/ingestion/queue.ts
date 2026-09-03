import { Queue } from "bullmq";
import IORedis from "ioredis";
import { config } from "../config";
import { FetchedReport } from "./fetcher";

const connection = new IORedis(config.redisUrl, { maxRetriesPerRequest: null });

export const ingestionQueue = new Queue<FetchedReport>("ingestion", {
  connection,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: "exponential",
      delay: 2000,
    },
    removeOnComplete: 100, // Keep last 100 completed jobs for debugging
    removeOnFail: 500,
  },
});

/**
 * Enqueues a batch of fetched reports for async embed + store processing.
 */
export async function enqueueReports(reports: FetchedReport[]): Promise<void> {
  const jobs = reports.map((report) => ({
    name: "embed-and-store",
    data: report,
    opts: {
      jobId: report.id, // Deduplicate by CVE ID
    },
  }));

  await ingestionQueue.addBulk(jobs);
  console.log(`Enqueued ${jobs.length} reports for ingestion`);
}
