// Lazy Postgres pool — no pool created until first query.
// Keeps this package importable in test mode without a DB.
import pg from "pg";

let _pool = null;

export function pool() {
  if (_pool) return _pool;
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL not set");
  _pool = new pg.Pool({ connectionString: url, max: 10, idleTimeoutMillis: 30_000 });
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
