// Next.js App-Router route wrapper.
// Usage:
//   import { withGuard } from "vigil-guard/next";
//   export const POST = withGuard(async (req, ctx) => { ... }, { field: "message" });
import { guard } from "./index.js";

export function withGuard(handler, opts = {}) {
  const g = guard(opts);
  const field = opts.field || "message";
  return async function (req, ctx) {
    try {
      const clone = req.clone ? req.clone() : req;
      let body = null;
      try { body = await clone.json(); } catch { /* not JSON; fall through */ }
      if (body && typeof body[field] === "string") {
        const r = g.checkInput(body[field]);
        if (r.blocked) {
          return new Response(JSON.stringify({ error: "vigil_guard_blocked", reason: r.reason, threats: r.threats }), { status: 400, headers: { "content-type": "application/json" } });
        }
        body[field] = r.sanitized;
        // hand a fresh Request with sanitized body downstream
        const newReq = new Request(req.url, { method: req.method, headers: req.headers, body: JSON.stringify(body) });
        newReq.vigil = { input: r };
        return handler(newReq, ctx);
      }
    } catch { /* never break the host app */ }
    return handler(req, ctx);
  };
}
