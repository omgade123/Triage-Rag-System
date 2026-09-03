import fs from "fs";
import path from "path";
import { pool } from "./pool";

/**
 * Runs all SQL migration files in the migrations/ directory, in order.
 * Simple sequential runner — no migration tracking table (fine for dev).
 */
export async function runMigrations(): Promise<void> {
  const migrationsDir = path.join(__dirname, "migrations");
  const files = fs.readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  for (const file of files) {
    const filePath = path.join(migrationsDir, file);
    const sql = fs.readFileSync(filePath, "utf-8");

    console.log(`Running migration: ${file}`);
    await pool.query(sql);
    console.log(`Completed migration: ${file}`);
  }
}
