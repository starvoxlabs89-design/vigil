import { q, qOne } from "./db.js";
import { newApiKey, hashToken } from "./tokens.js";
import { readJson, json } from "./util.js";
import { requireUser } from "./auth.js";

// GET /me/keys — list (never return full key, only prefix + name + created)
export async function listKeys(req, res) {
  const u = await requireUser(req);
  if (!u) return json(res, 401, { error: "not signed in" });
  const rows = await q(
    "SELECT id, name, prefix, last_used_at, revoked_at, created_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC",
    [u.id],
  );
  return json(res, 200, { keys: rows });
}

// POST /me/keys — create. Returns the FULL key ONCE.
export async function createKey(req, res) {
  const u = await requireUser(req);
  if (!u) return json(res, 401, { error: "not signed in" });
  const body = await readJson(req).catch(() => ({}));
  const name = String(body.name || "default").slice(0, 60) || "default";
  const k = newApiKey();
  await q(
    "INSERT INTO api_keys(user_id, name, prefix, key_hash) VALUES($1,$2,$3,$4)",
    [u.id, name, k.prefix, k.hash],
  );
  return json(res, 200, { name, prefix: k.prefix, key: k.full, note: "Save this now — it won't be shown again." });
}

// POST /me/keys/:id/revoke
export async function revokeKey(req, res, id) {
  const u = await requireUser(req);
  if (!u) return json(res, 401, { error: "not signed in" });
  const n = parseInt(id, 10);
  if (!Number.isFinite(n)) return json(res, 400, { error: "bad id" });
  const row = await qOne(
    "UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL RETURNING id",
    [n, u.id],
  );
  if (!row) return json(res, 404, { error: "not found" });
  return json(res, 200, { ok: true });
}

// Auth helper for the /ingest endpoint. Looks up the user by hashed API key.
export async function userByApiKey(rawKey) {
  if (!rawKey || typeof rawKey !== "string") return null;
  const row = await qOne(
    `SELECT k.id AS key_id, u.id, u.email, u.plan
     FROM api_keys k JOIN users u ON u.id = k.user_id
     WHERE k.key_hash=$1 AND k.revoked_at IS NULL`,
    [hashToken(rawKey)],
  );
  if (row) q("UPDATE api_keys SET last_used_at=NOW() WHERE id=$1", [row.key_id]).catch(() => {});
  return row;
}
