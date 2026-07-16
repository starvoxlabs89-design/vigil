// Lazy Postgres pool — no pool created until first query.
// Keeps this package importable in test mode without a DB.
//
// Works with local Postgres OR a hosted Postgres like Supabase. For Supabase,
// set DATABASE_URL to the *Session pooler* string (…pooler.supabase.com:5432)
// — a long-lived pg.Pool needs session mode, not the 6543 transaction pooler
// (which disables the prepared statements pg uses for parameterised queries).
import pg from "pg";

let _pool = null;

// SSL policy: localhost → none; anything remote (Supabase etc.) → TLS on.
// Supabase's pooler cert doesn't always chain to Node's trust store, so we
// don't hard-fail verification unless DATABASE_SSL=strict is set explicitly.
function sslFor(url) {
  let host = "";
  try { host = new URL(url).hostname; } catch { /* leave blank */ }
  const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "";
  if (isLocal && process.env.DATABASE_SSL !== "require") return false;
  return { rejectUnauthorized: process.env.DATABASE_SSL === "strict" };
}

export function pool() {
  if (_pool) return _pool;
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL not set");
  _pool = new pg.Pool({ connectionString: url, ssl: sslFor(url), max: 10, idleTimeoutMillis: 30_000 });
  return _pool;
}

export async function q(sql, params = []) {
  const p = pool();
  const res = await p.query(sql, params);
  return res.rows;
}

export async function qOne(sql, params = []) {
  const rows = await q(sql, params);
  return rows[0] || null;
}
