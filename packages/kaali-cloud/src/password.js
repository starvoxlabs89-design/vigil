import { scrypt, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

// Node built-in scrypt — no bcrypt native dep. Recommended params (~64MB, ~50ms).
// Format: scrypt$N$r$p$salt_b64$hash_b64
const N = 2 ** 15;      // 32768 iterations
const r = 8;
const p = 1;
const KEY_LEN = 64;
const SALT_LEN = 16;

const scryptAsync = promisify(scrypt);

export async function hashPassword(plain) {
  if (typeof plain !== "string" || plain.length < 8) throw new Error("password too short (min 8)");
  if (plain.length > 512) throw new Error("password too long");
  const salt = randomBytes(SALT_LEN);
  const derived = await scryptAsync(plain, salt, KEY_LEN, { N, r, p, maxmem: 128 * 1024 * 1024 });
  return `scrypt$${N}$${r}$${p}$${salt.toString("base64")}$${derived.toString("base64")}`;
}

export async function verifyPassword(plain, stored) {
  try {
    const parts = String(stored || "").split("$");
    if (parts.length !== 6 || parts[0] !== "scrypt") return false;
    const [, Ns, rs, ps, saltB64, hashB64] = parts;
    const N = parseInt(Ns, 10), r = parseInt(rs, 10), p = parseInt(ps, 10);
    if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;
    const salt = Buffer.from(saltB64, "base64");
    const expected = Buffer.from(hashB64, "base64");
    const derived = await scryptAsync(plain, salt, expected.length, { N, r, p, maxmem: 128 * 1024 * 1024 });
    return derived.length === expected.length && timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}
