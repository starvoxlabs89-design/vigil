import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { finding } from "../util.js";

// India-DPDP differentiator: detect Indian PII (Aadhaar, PAN, etc.) sitting in
// source, logs, or fixtures — the kind of leak that triggers DPDP penalties.
export const meta = {
  id: "pii",
  title: "Indian PII / DPDP exposure",
  applies: (t) => !/^https?:\/\//i.test(t),
};

// Verhoeff checksum — Aadhaar's real validation, to cut false positives.
const D = [
  [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
  [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
  [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0],
];
const P = [
  [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
  [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
  [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
];
function verhoeffValid(num) {
  let c = 0;
  const digits = num.replace(/\D/g, "").split("").reverse().map(Number);
  for (let i = 0; i < digits.length; i++) c = D[c][P[i % 8][digits[i]]];
  return c === 0;
}

const DPDP_URL = "https://www.meity.gov.in/data-protection-framework";
const PATTERNS = [
  {
    id: "aadhaar", sev: "critical", title: "Aadhaar number", re: /\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b/g, validate: verhoeffValid, dpdp: "sensitive-identifier",
    attack: "A valid Aadhaar in code or logs is a reportable personal-data breach the moment those logs ship to a dashboard, a backup, or a third party. It links to biometrics and can't be reissued like a password.",
    learn: "Aadhaar is among the most sensitive identifiers under Indian law. Logs and fixtures are the surface teams forget — data-at-rest scanners never look there.",
    learnUrl: DPDP_URL,
  },
  {
    id: "pan", sev: "high", title: "PAN (Permanent Account Number)", re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, dpdp: "financial-identifier",
    attack: "A PAN ties a person to their tax and financial identity. Leaked alongside a name it's enough to seed identity fraud and phishing.",
    learn: "Financial identifiers demand encryption at rest and strict access — don't let them sit in plaintext source or logs.",
    learnUrl: DPDP_URL,
  },
  {
    id: "phone-in", sev: "medium", title: "Indian mobile number", re: /\b(?:\+?91[\-\s]?)?[6-9][0-9]{9}\b/g, dpdp: "contact-data",
    attack: "Bulk phone numbers in a repo become a spam/SIM-swap/OTP-phishing list the day the repo leaks.",
    learn: "Contact data is still personal data under DPDP — minimize what you store and never hardcode real numbers in fixtures.",
    learnUrl: DPDP_URL,
  },
  {
    id: "email", sev: "low", title: "Email address", re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, dpdp: "contact-data",
    attack: "Real user emails in source feed phishing and credential-stuffing lists if the code is ever exposed.",
    learn: "Use example.com / placeholder addresses in code and tests; keep real contact data out of the repo.",
    learnUrl: DPDP_URL,
  },
];

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "vendor", "__pycache__"]);
const SKIP_EXT = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".lock"]);

async function* walk(dir, depth = 0) {
  if (depth > 8) return;
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".env") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) yield* walk(p, depth + 1); }
    else if (!SKIP_EXT.has(extname(e.name))) yield p;
  }
}

export async function run(target) {
  const findings = [];
  const seen = new Set();
  let isDir = false;
  try { isDir = (await stat(target)).isDirectory(); } catch {
    return [finding({ id: "pii-nopath", title: "Path not found", severity: "info", detail: target })];
  }
  const files = [];
  if (isDir) { for await (const f of walk(target)) files.push(f); } else { files.push(target); }

  for (const file of files.slice(0, 5000)) {
    let txt;
    try { txt = await readFile(file, "utf8"); } catch { continue; }
    if (txt.length > 2_000_000) continue;
    for (const pat of PATTERNS) {
      for (const m of txt.matchAll(pat.re)) {
        const val = m[0];
        if (pat.validate && !pat.validate(val)) continue;
        const key = `${pat.id}:${val}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push(finding({
          id: `pii-${pat.id}`, title: pat.title, severity: pat.sev,
          detail: `${file}`, evidence: val.slice(0, 4) + "…" + val.slice(-2),
          dpdp: pat.dpdp,
          fix: "Remove from source/logs; redact before logging; store encrypted; minimize & set a retention window per DPDP.",
          attack: pat.attack, learn: pat.learn, learnUrl: pat.learnUrl,
        }));
      }
    }
  }
  return findings;
}
