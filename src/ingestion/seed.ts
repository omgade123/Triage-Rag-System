import { fetchCvePage, delay } from "./fetcher";
import { enqueueReports, ingestionQueue } from "./queue";
import { config } from "../config";


/**
 * CLI script to seed the database by fetching CVEs from NVD and
 * pushing them through the ingestion queue.
 *
 * Usage: npx ts-node src/ingestion/seed.ts [maxRecords]
 * Example: npx ts-node src/ingestion/seed.ts 200
 */
async function seed() {
  const maxRecords = parseInt(process.argv[2] || "200", 10);
  const pageSize = 50;
  let startIndex = 0;
  let totalFetched = 0;

  console.log(`Seeding up to ${maxRecords} CVE records from NVD...`);

  while (totalFetched < maxRecords) {
    const remaining = maxRecords - totalFetched;
    const currentPageSize = Math.min(pageSize, remaining);

    console.log(
      `Fetching page: startIndex=${startIndex}, pageSize=${currentPageSize}`
    );

    const { reports, totalResults } = await fetchCvePage(
      startIndex,
      currentPageSize
    );

    if (reports.length === 0) {
      console.log("No more records from NVD.");
      break;
    }

    // Enqueue for async embed + store
    await enqueueReports(reports);

    totalFetched += reports.length;
    startIndex += reports.length;

    console.log(
      `Fetched ${totalFetched}/${Math.min(maxRecords, totalResults)} records`
    );

    // Rate limit: wait 7s between requests if no API key, 1s with key
    const waitMs = config.nvdApiKey ? 1000 : 7000;
    if (totalFetched < maxRecords) {
      console.log(`Waiting ${waitMs}ms for rate limit...`);
      await delay(waitMs);
    }
  }

  console.log(`Seeding complete. ${totalFetched} records enqueued.`);
  await ingestionQueue.close();
  process.exit(0);
}

seed().catch((err) => {
  console.error("Seed failed:", err);
  process.exit(1);
});
