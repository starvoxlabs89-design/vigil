import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { finding } from "../util.js";

// Scans a local directory/file tree for committed secrets.
export const meta = {
  id: "secrets",
  title: "Hardcoded secrets",
  applies: (t) => !/^https?:\/\//i.test(t),
};

const PATTERNS = [
  { id: "aws-akid", sev: "critical", title: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/ },
  { id: "openai", sev: "critical", title: "OpenAI API key", re: /sk-[A-Za-z0-9]{20,}/ },
  { id: "anthropic", sev: "critical", title: "Anthropic API key", re: /sk-ant-[A-Za-z0-9_\-]{20,}/ },
  { id: "google", sev: "high", title: "Google API key", re: /AIza[0-9A-Za-z\-_]{35}/ },
  { id: "slack", sev: "high", title: "Slack token", re: /xox[baprs]-[0-9A-Za-z\-]{10,}/ },
  { id: "jwt", sev: "medium", title: "JWT", re: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/ },
  { id: "pk", sev: "critical", title: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { id: "generic", sev: "medium", title: "Generic hardcoded secret", re: /(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['"][^'"]{8,}['"]/i },
];

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "vendor", "__pycache__"]);
const SKIP_EXT = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".lock", ".min.js"]);

async function* walk(dir, depth = 0) {
  if (depth > 8) return;
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".env") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(p, depth + 1);
    } else if (!SKIP_EXT.has(extname(e.name))) {
      yield p;
    }
  }
}

export async function run(target) {
  const findings = [];
  let isDir = false;
  try { isDir = (await stat(target)).isDirectory(); } catch {
    return [finding({ id: "secrets-nopath", title: "Path not found", severity: "info", detail: target })];
  }
  const files = [];
  if (isDir) { for await (const f of walk(target)) files.push(f); } else { files.push(target); }

  for (const file of files.slice(0, 5000)) {
    let txt;
    try { txt = await readFile(file, "utf8"); } catch { continue; }
    if (txt.length > 2_000_000) continue;
    const lines = txt.split("\n");
    for (let i = 0; i < lines.length; i++) {
      for (const pat of PATTERNS) {
        const m = lines[i].match(pat.re);
        if (m) {
          findings.push(finding({
            id: `secret-${pat.id}`, title: pat.title, severity: pat.sev,
            detail: `${file}:${i + 1}`,
            evidence: m[0].slice(0, 12) + "…",
            owasp: "OWASP-Web",
            fix: "# 1. rotate the key at the provider (this one is now burned)\n# 2. move it to an env var / secret manager, never in code\n# 3. purge it from git history (git-filter-repo / BFG)",
            attack: `Anyone who reads this file — a leaked repo, a shipped bundle, a former employee — has a live ${pat.title.replace(/ API key| token| block/i, "")} credential. Committing to git means it lives in history even after you delete the line.`,
            learn: "A secret that has touched source control is compromised — rotate first, then remove. Scrubbing the line without rotating does nothing.",
            learnUrl: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
          }));
        }
      }
    }
  }
  return findings;
}
