import { c, SEVERITY, vigilScore } from "./util.js";

// Human-readable terminal report. Also supports --json for CI.
export function printReport(target, results) {
  const all = results.flatMap((r) => r.findings.map((f) => ({ ...f, scanner: r.scanner })));
  all.sort((a, b) => (SEVERITY[b.severity].rank - SEVERITY[a.severity].rank));

  console.log("");
  console.log(c.bold(`  Vigil report — ${target}`));
  console.log(c.gray(`  ${new Date().toISOString()}`));
  console.log("");

  if (all.length === 0) {
    console.log(c.green("  ✓ No findings. Clean — for the checks that ran."));
  }

  for (const f of all) {
    const sev = SEVERITY[f.severity];
    const tags = [
      f.owasp ? c.magenta(f.owasp) : null,
      f.dpdp ? c.cyan(`DPDP:${f.dpdp}`) : null,
    ].filter(Boolean).join(" ");
    console.log(`  ${sev.color(`[${sev.label}]`)} ${c.bold(f.title)} ${c.gray(`(${f.scanner})`)}`);
    if (f.detail) console.log(`     ${f.detail}`);
    if (f.evidence) console.log(c.dim(`     evidence: ${f.evidence}`));
    if (tags) console.log(`     ${tags}`);
    if (f.fix) console.log(c.green(`     fix: ${f.fix}`));
    console.log("");
  }

  const score = vigilScore(all);
  const scoreColor = score >= 80 ? c.green : score >= 50 ? c.yellow : c.red;
  const counts = ["critical", "high", "medium", "low", "info"]
    .map((s) => `${all.filter((f) => f.severity === s).length} ${s}`)
    .join("  ");
  console.log(c.bold("  ─────────────────────────────────────────────"));
  console.log(`  Vigil Score: ${scoreColor(c.bold(score + "/100"))}    ${c.gray(counts)}`);
  console.log("");
  return { target, score, findings: all };
}

export function jsonReport(target, results) {
  const all = results.flatMap((r) => r.findings.map((f) => ({ ...f, scanner: r.scanner })));
  return JSON.stringify(
    { target, timestamp: new Date().toISOString(), score: vigilScore(all), findings: all },
    null,
    2
  );
}

// SARIF 2.1.0 — the format GitHub code-scanning ingests for inline PR annotations.
const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

export function sarifReport(target, results) {
  const all = results.flatMap((r) => r.findings.map((f) => ({ ...f, scanner: r.scanner })));
  const rules = new Map();
  const sarifResults = [];

  for (const f of all) {
    if (!rules.has(f.id)) {
      rules.set(f.id, {
        id: f.id,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.fix || f.detail || f.title },
        defaultConfiguration: { level: SARIF_LEVEL[f.severity] || "note" },
        properties: { security_severity: { critical: "9.0", high: "7.5", medium: "5.0", low: "3.0", info: "0.0" }[f.severity] || "0.0", tags: ["security", f.owasp, f.dpdp ? "dpdp" : null].filter(Boolean) },
      });
    }
    // Try to recover a file:line from the detail field for inline annotation.
    const m = (f.detail || "").match(/^(.+?):(\d+)$/) || (f.detail || "").match(/^(\S+\.\w+)$/);
    const location = m
      ? [{ physicalLocation: { artifactLocation: { uri: m[1] }, ...(m[2] ? { region: { startLine: Number(m[2]) } } : {}) } }]
      : [{ physicalLocation: { artifactLocation: { uri: target } } }];

    sarifResults.push({
      ruleId: f.id,
      level: SARIF_LEVEL[f.severity] || "note",
      message: { text: [f.detail, f.evidence ? `(evidence: ${f.evidence})` : "", f.fix ? `Fix: ${f.fix}` : ""].filter(Boolean).join(" ") || f.title },
      locations: location,
    });
  }

  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "Vigil",
        informationUri: "https://github.com/your-org/vigil",
        version: "0.1.0",
        rules: [...rules.values()],
      } },
      results: sarifResults,
    }],
  }, null, 2);
}
