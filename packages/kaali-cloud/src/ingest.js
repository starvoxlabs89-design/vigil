import { q } from "./db.js";
import { readJson, json, clientIp } from "./util.js";
import { userByApiKey } from "./keys.js";
import { limit } from "./ratelimit.js";

// POST /ingest — receives events from the CLI (`kaali scan --cloud-key K`)
// and the guard (`onEvent`). Auth via Bearer token or ?key=.
export async function ingest(req, res) {
  const auth = req.headers.authorization || "";
  const url = new URL(req.url, "http://x");
  const rawKey = auth.startsWith("Bearer ") ? auth.slice(7) : url.searchParams.get("key");
  const u = await userByApiKey(rawKey);
  if (!u) return json(res, 401, { error: "invalid api key" });

  const ip = clientIp(req);
  if (!limit(`ingest:key:${u.id}`, 600, 60 * 1000)) return json(res, 429, { error: "rate limited" });

  const body = await readJson(req, 500_000).catch(() => null);
  if (!body) return json(res, 400, { error: "bad json" });

  // Accept two shapes:
  // 1) CLI scan report:  { source:'cli', target, score, findings: [...] }
  // 2) Guard event:      { source:'guard', direction, threats, pii, blocked, target? }
  const source = body.source === "guard" ? "guard" : "cli";
  const target = body.target ? String(body.target).slice(0, 500) : null;
  const score = Number.isFinite(body.score) ? Math.max(0, Math.min(100, body.score | 0)) : null;
  const payload = source === "cli" ? { findings: body.findings || [] } : {
    direction: body.direction, threats: body.threats || [], pii: body.pii || [],
    blocked: !!body.blocked, reason: body.reason || null,
  };

  await q(
    "INSERT INTO events(user_id, source, target, score, payload) VALUES($1,$2,$3,$4,$5)",
    [u.id, source, target, score, payload],
  );
  return json(res, 200, { ok: true });
}
