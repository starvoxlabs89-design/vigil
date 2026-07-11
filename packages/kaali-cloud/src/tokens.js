import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// Opaque random tokens (session cookies, verify/reset tokens, API keys).
// Never store the raw token — always its SHA-256 hash. Verify with a
// timing-safe compare.

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function hashToken(tok) {
  return createHash("sha256").update(String(tok)).digest("hex");
}

export function safeCompareHex(a, b) {
  const ab = Buffer.from(String(a), "hex");
  const bb = Buffer.from(String(b), "hex");
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

// API key format: k_live_<24 base64url chars>. Prefix used for UI display.
export function newApiKey() {
  const secret = randomToken(24);
  const full = `k_live_${secret}`;
  return { full, prefix: full.slice(0, 12), hash: hashToken(full) };
}
