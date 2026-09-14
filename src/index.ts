import express from "express";
import path from "path";
import { config } from "./config";
import { runMigrations } from "./db/migrate";
import { triageRouter } from "./routes/triage";
import { startWorker } from "./ingestion/worker";

async function main() {
  // Run database migrations
  console.log("Running database migrations...");
  await runMigrations();
  console.log("Migrations complete.");

  // Start BullMQ ingestion worker
  console.log("Starting ingestion worker...");
  const worker = startWorker();
  console.log("Ingestion worker started.");

  // Set up Express app
  const app = express();
  app.use(express.json());

  // Health check
  app.get("/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // Triage routes
  app.use("/triage", triageRouter);

  // Serve the static frontend (public/ lives at the repo root, one level up
  // from the compiled dist/ dir and from src/ when running via tsx).
  const publicDir = path.resolve(__dirname, "..", "public");
  app.use(express.static(publicDir));

  // Start server
  app.listen(config.port, () => {
    console.log(`Triage RAG System listening on port ${config.port}`);
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.log("Shutting down...");
    await worker.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
