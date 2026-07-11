import { detect, redact, checkToolCall, CANARY_MARKER } from "./detect.js";

// Kaali Guard — the runtime API.
//
// Two entry points:
//   const g = guard({...})       for library / framework users
//     g.checkInput(text)         → { allowed, blocked, reason, sanitized, threats, pii }
//     g.checkOutput(text)        → { allowed, blocked, reason, sanitized, threats, pii }
//     g.checkToolCall({name, args})
//     g.middleware({...})        → Express-compatible middleware
//
// Everything is pure, zero-dependency, synchronous. Latency is regex-bound
// (single-digit ms on typical prompt sizes). No network calls.

const DEFAULT_BLOCK = ["prompt-injection", "invisible-unicode"];
const DEFAULT_REDACT = ["aadhaar", "pan", "phone_in", "email"];

export function guard(opts = {}) {
  const {
    block = DEFAULT_BLOCK,     // threat types to REFUSE the request on
    redactTypes = DEFAULT_REDACT,   // PII types to mask (in + out)
    stripInvisibleChars = true,
    mcp = null,                // { allow: [...], deny: [...] } — tool-call firewall
    onEvent = null,            // (evt) => void — stream to Kaali Cloud / your logger
    mode = "block",            // "block" | "monitor"  (monitor = observe only)
  } = opts;

  const emit = (evt) => { try { onEvent && onEvent(evt); } catch { /* never break the app */ } };

  function _decide(direction, text) {
    const d = detect(text);
    const blocking = d.threats.filter((t) => block.includes(t.type));
    const sanitized = redact(text, { types: redactTypes, stripInvisibleChars });
    const evt = { direction, threats: d.threats, pii: d.pii.map((p) => p.type), blocked: mode === "block" && blocking.length > 0, ts: Date.now() };
    emit(evt);
    return {
      allowed: !evt.blocked,
      blocked: evt.blocked,
      reason: blocking[0]?.type || null,
      threats: d.threats,
      pii: d.pii,
      sanitized,
    };
  }

  return {
    checkInput: (text) => _decide("input", text),
    checkOutput: (text) => _decide("output", text),
    checkToolCall: (call) => {
      const res = checkToolCall(call, mcp || {});
      emit({ direction: "tool-call", call: call.name, allowed: res.allowed, violations: res.violations, ts: Date.now() });
      return res;
    },
    redact: (text) => redact(text, { types: redactTypes, stripInvisibleChars }),
    middleware: (mopts = {}) => makeExpressMiddleware(_decide, mopts),
    _detect: detect,
  };
}

// Express/Connect-style middleware for the common shape:
//   POST /chat  { message: "..." }
// Inspects req.body[field], blocks or sanitizes in-place. Response protection
// requires wrapping res.json / res.send — do that opt-in via wrapResponse.
function makeExpressMiddleware(decide, { field = "message", wrapResponse = false } = {}) {
  return function kaaliGuardMiddleware(req, res, next) {
    try {
      const value = req.body?.[field];
      if (typeof value === "string" && value.length) {
        const r = decide("input", value);
        if (r.blocked) {
          res.statusCode = 400;
          res.setHeader("content-type", "application/json");
          return res.end(JSON.stringify({ error: "kaali_guard_blocked", reason: r.reason, threats: r.threats }));
        }
        req.body[field] = r.sanitized;   // continue with sanitized text
        req.kaali = { input: r };
      }
      if (wrapResponse && res.json) {
        const origJson = res.json.bind(res);
        res.json = (payload) => {
          const asText = typeof payload === "string" ? payload : JSON.stringify(payload);
          const r = decide("output", asText);
          if (r.blocked) return origJson({ error: "kaali_guard_blocked_output", reason: r.reason });
          try { return origJson(JSON.parse(r.sanitized)); } catch { return origJson(r.sanitized); }
        };
      }
      next();
    } catch (e) {
      // never break the host app
      next();
    }
  };
}

export { detect, redact, checkToolCall, CANARY_MARKER };
