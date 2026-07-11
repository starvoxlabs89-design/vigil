// Run the initial migration. Idempotent (uses IF NOT EXISTS).
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { pool } from "./db.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dir = join(__dirname, "..", "migrations");

const files = (await readdir(dir)).filter((f) => f.endsWith(".sql")).sort();
const p = pool();
for (const f of files) {
  const sql = await readFile(join(dir, f), "utf8");
  console.log(`Applying ${f}...`);
  await p.query(sql);
}
console.log("Migrations complete.");
await p.end();
