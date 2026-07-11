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

// Severity ordering + weights drive the Kaali Score.
export const SEVERITY = {
  critical: { rank: 4, weight: 40, color: c.red, label: "CRITICAL" },
  high: { rank: 3, weight: 20, color: c.red, label: "HIGH" },
  medium: { rank: 2, weight: 8, color: c.yellow, label: "MEDIUM" },
  low: { rank: 1, weight: 3, color: c.blue, label: "LOW" },
  info: { rank: 0, weight: 0, color: c.gray, label: "INFO" },
};

// A finding. `attack`/`learn` power the teaching (report-card) output; optional
// everywhere so older scanners keep working — the renderer degrades gracefully.
export function finding({ id, title, severity, detail, evidence, owasp, dpdp, fix, attack, learn, learnUrl }) {
  return { id, title, severity, detail, evidence, owasp, dpdp, fix, attack, learn, learnUrl };
}

// 0 (worst) .. 100 (clean). Saturating decay, not linear subtraction: severity
// weights accumulate as `penalty`, then score = 100·e^(−penalty/K). This keeps
// resolution — a page with two criticals reads worse than one instead of both
// flooring at 0 — so the grade actually moves as you fix things.
const SCORE_K = 80;
export function kaaliScore(findings) {
  let penalty = 0;
  for (const f of findings) penalty += SEVERITY[f.severity]?.weight ?? 0;
  return Math.round(100 * Math.exp(-penalty / SCORE_K));
}

// Letter grade for a 0..100 score (standard US scale, with +/-). `band` is the
// coarse bucket (a/b/c/d/f) used to pick a color.
export function letterGrade(score) {
  const table = [
    [97, "A+"], [93, "A"], [90, "A-"],
    [87, "B+"], [83, "B"], [80, "B-"],
    [77, "C+"], [73, "C"], [70, "C-"],
    [67, "D+"], [63, "D"], [60, "D-"],
    [0, "F"],
  ];
  const letter = table.find(([min]) => score >= min)[1];
  return { letter, band: letter[0].toLowerCase() };
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
