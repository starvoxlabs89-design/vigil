import { q } from "./db.js";
import { json } from "./util.js";
import { requireUser } from "./auth.js";

// GET /me/events?limit=50 — recent scan + guard events
export async function recentEvents(req, res) {
  const u = await requireUser(req);
  if (!u) return json(res, 401, { error: "not signed in" });
  const url = new URL(req.url, "http://x");
  const lim = Math.min(200, Math.max(1, parseInt(url.searchParams.get("limit") || "50", 10)));
  const rows = await q(
    `SELECT id, source, target, score, payload, created_at
     FROM events WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`,
    [u.id, lim],
  );
  return json(res, 200, { events: rows });
}

// GET /me/stats — a small at-a-glance rollup for the dashboard header
export async function stats(req, res) {
  const u = await requireUser(req);
  if (!u) return json(res, 401, { error: "not signed in" });
  const rows = await q(
    `SELECT
        COUNT(*) FILTER (WHERE source='cli')                          AS scans,
        COUNT(*) FILTER (WHERE source='guard')                        AS guard_events,
        COUNT(*) FILTER (WHERE source='guard' AND (payload->>'blocked')::boolean = true) AS guard_blocks,
        AVG(score) FILTER (WHERE source='cli' AND score IS NOT NULL)  AS avg_score,
        MAX(created_at)                                               AS last_event
     FROM events WHERE user_id=$1 AND created_at > NOW() - INTERVAL '30 days'`,
    [u.id],
  );
  const r = rows[0] || {};
  return json(res, 200, {
    scans_30d: Number(r.scans || 0),
    guard_events_30d: Number(r.guard_events || 0),
    guard_blocks_30d: Number(r.guard_blocks || 0),
    avg_score_30d: r.avg_score != null ? Math.round(Number(r.avg_score)) : null,
    last_event: r.last_event,
  });
}
