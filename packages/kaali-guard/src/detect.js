// Detection primitives — the same signals the Kaali scanner uses, but shaped
// for one-shot, in-the-request-path use. All checks are pure functions.

const CANARY_MARKER = "KAALI_GUARD_CANARY_9317";

// --- Prompt-injection heuristics ---------------------------------------------
const INJECT_RE = [
  /ignore (all |the |your |any )?(previous|prior|above) (instructions|prompt|messages)/i,
  /\b(ai|assistant|model|agent|llm|chatbot|system)[:\s,].{0,60}(ignore|disregard|instead|must|output|print|reply|append|reveal|forget|tell|email|send)/i,
  /system\s*(override|prompt|directive|instruction|role)\b/i,
  /do not (tell|reveal|mention|inform) the user/i,
  /(exfiltrate|send|email|post).{0,50}(https?:|password|api[_-]?key|secret|token|to (the )?url)/i,
  /you are (now|actually) (a |an )?(dan|jailbroken|unrestricted|different)/i,
  /\bBEGIN\s+(SYSTEM|ADMIN)\b|\bEND\s+(SYSTEM|ADMIN)\b/i,
];

// --- Invisible / steganographic unicode --------------------------------------
const INVISIBLE_RE = /[\u{E0000}-\u{E007F}​-‏‪-‮⁠-⁤⁦-⁩﻿]/u;
function decodeTagChars(text) {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0000 && cp <= 0xe007f) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}
function stripInvisible(text) {
  return text.replace(INVISIBLE_RE, "");
}

// --- Indian PII (DPDP) -------------------------------------------------------
const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function verhoeffValid(num) {
  let c = 0;
  const digits = num.replace(/\D/g, "").split("").reverse().map(Number);
  if (digits.length !== 12) return false;
  for (let i = 0; i < digits.length; i++) c = D[c][P[i % 8][digits[i]]];
  return c === 0;
}
const PII_PATTERNS = {
  aadhaar:  { re: /\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b/g, validate: verhoeffValid, mask: (s) => `XXXX-XXXX-${s.replace(/\s/g, "").slice(-4)}` },
  pan:      { re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, mask: (s) => s.slice(0, 3) + "XXXXXX" },
  phone_in: { re: /\b(?:\+?91[\-\s]?)?[6-9][0-9]{9}\b/g, mask: (s) => s.slice(0, 3) + "XXXXXXX" },
  email:    { re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, mask: (s) => { const [u, d] = s.split("@"); return u.slice(0, 2) + "***@" + d; } },
};

// --- Public API --------------------------------------------------------------

// Detect: returns {threats:[], invisible:boolean, pii:[]}
export function detect(text) {
  const threats = [];
  const t = String(text ?? "");

  // 1) Invisible unicode — always suspicious; decode + re-check for instructions.
  const hasInvisible = INVISIBLE_RE.test(t);
  if (hasInvisible) {
    const decoded = decodeTagChars(t);
    const decodedIsInstruction = decoded && INJECT_RE.some((r) => r.test(decoded));
    threats.push({
      type: "invisible-unicode",
      severity: decodedIsInstruction ? "critical" : "high",
      detail: decodedIsInstruction ? `hidden instruction: "${decoded.slice(0, 120)}"` : "invisible/steganographic characters present",
    });
  }

  // 2) Prompt-injection heuristics (against the visible + decoded text).
  const stripped = hasInvisible ? stripInvisible(t) + " " + decodeTagChars(t) : t;
  for (const re of INJECT_RE) {
    const m = stripped.match(re);
    if (m) { threats.push({ type: "prompt-injection", severity: "high", detail: m[0].slice(0, 120) }); break; }
  }

  // 3) PII scan
  const pii = [];
  for (const [name, pat] of Object.entries(PII_PATTERNS)) {
    for (const m of t.matchAll(pat.re)) {
      const val = m[0];
      if (pat.validate && !pat.validate(val)) continue;
      pii.push({ type: name, value: val, index: m.index });
    }
  }

  return { threats, invisible: hasInvisible, pii };
}

// Redact: rewrite text with PII masked and invisible chars stripped.
export function redact(text, { types = ["aadhaar", "pan", "phone_in", "email"], stripInvisibleChars = true } = {}) {
  let t = String(text ?? "");
  if (stripInvisibleChars) t = stripInvisible(t);
  for (const name of types) {
    const pat = PII_PATTERNS[name];
    if (!pat) continue;
    t = t.replace(pat.re, (m) => (pat.validate && !pat.validate(m) ? m : pat.mask(m)));
  }
  return t;
}

export { stripInvisible };

// MCP tool-call firewall: decide whether an agent's proposed tool call is safe.
export function checkToolCall({ name, args }, { allow, deny } = {}) {
  const violations = [];
  if (allow && !allow.includes(name)) violations.push({ type: "tool-not-allowlisted", severity: "critical", detail: name });
  if (deny && deny.includes(name)) violations.push({ type: "tool-denylisted", severity: "critical", detail: name });
  const argStr = typeof args === "string" ? args : JSON.stringify(args ?? {});
  const argDetect = detect(argStr);
  for (const th of argDetect.threats) violations.push({ ...th, detail: `in tool args: ${th.detail}` });
  return { allowed: violations.length === 0, violations };
}

export { CANARY_MARKER };
