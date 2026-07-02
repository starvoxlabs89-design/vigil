// Zero-dependency helpers: ANSI color + severity model.

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));

export const c = {
  red: wrap(31),
  green: wrap(32),
  yellow: wrap(33),
  blue: wrap(34),
  magenta: wrap(35),
  cyan: wrap(36),
  gray: wrap(90),
  bold: wrap(1),
  dim: wrap(2),
};

// Severity ordering + weights drive the Vigil Score.
export const SEVERITY = {
  critical: { rank: 4, weight: 40, color: c.red, label: "CRITICAL" },
  high: { rank: 3, weight: 20, color: c.red, label: "HIGH" },
  medium: { rank: 2, weight: 8, color: c.yellow, label: "MEDIUM" },
  low: { rank: 1, weight: 3, color: c.blue, label: "LOW" },
  info: { rank: 0, weight: 0, color: c.gray, label: "INFO" },
};

export function finding({ id, title, severity, detail, evidence, owasp, dpdp, fix }) {
  return { id, title, severity, detail, evidence, owasp, dpdp, fix };
}

// 0 (worst) .. 100 (clean). Caps so a single critical can't be hidden by many infos.
export function vigilScore(findings) {
  let penalty = 0;
  for (const f of findings) penalty += SEVERITY[f.severity]?.weight ?? 0;
  return Math.max(0, 100 - penalty);
}

export async function timedFetch(url, opts = {}, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}
