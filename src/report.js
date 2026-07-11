import { c, SEVERITY, kaaliScore, letterGrade } from "./util.js";

// Human-readable terminal report. Also supports --json for CI.
export function printReport(target, results) {
  const all = results.flatMap((r) => r.findings.map((f) => ({ ...f, scanner: r.scanner })));
  all.sort((a, b) => (SEVERITY[b.severity].rank - SEVERITY[a.severity].rank));

  console.log("");
  console.log(c.bold(`  Kaali report — ${target}`));
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

  const score = kaaliScore(all);
  const scoreColor = score >= 80 ? c.green : score >= 50 ? c.yellow : c.red;
  const counts = ["critical", "high", "medium", "low", "info"]
    .map((s) => `${all.filter((f) => f.severity === s).length} ${s}`)
    .join("  ");
  console.log(c.bold("  ─────────────────────────────────────────────"));
  console.log(`  Kaali Score: ${scoreColor(c.bold(score + "/100"))}    ${c.gray(counts)}`);
  console.log("");
  return { target, score, findings: all };
}

export function jsonReport(target, results) {
  const all = results.flatMap((r) => r.findings.map((f) => ({ ...f, scanner: r.scanner })));
  return JSON.stringify(
    { target, timestamp: new Date().toISOString(), score: kaaliScore(all), findings: all },
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
        name: "Kaali",
        informationUri: "https://github.com/starvoxlabs89-design/kaali",
        version: "0.1.0",
        rules: [...rules.values()],
      } },
      results: sarifResults,
    }],
  }, null, 2);
}

// ── HTML "report card" — the teaching output. Self-contained doc, no deps.
//    `kaali scan <t> --html > report.html`. opts.prevScore (optional) draws the trend.
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]));
const BAND_COLOR = { a: "#45D19A", b: "#8BD46A", c: "#F1C84A", d: "#FF9D46", f: "#FF5D5D" };
const SEV_BAND = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };

function lessonRow(k, cls, htmlValue) {
  return `<div class="lesson ${cls}"><div class="k">${k}</div><div class="v">${htmlValue}</div></div>`;
}

function cardHtml(f) {
  const band = SEV_BAND[f.severity] || "info";
  const tags = [
    f.owasp ? `<span class="tag owasp">${esc(f.owasp)}</span>` : "",
    f.dpdp ? `<span class="tag dpdp">DPDP: ${esc(f.dpdp)}</span>` : "",
  ].join("");

  const rows = [];
  const foundBits = [
    f.evidence ? `<span class="evidence">${esc(f.evidence)}</span>` : "",
    f.detail ? `<span class="muted">${esc(f.detail)}</span>` : "",
  ].filter(Boolean).join(" ");
  if (foundBits) rows.push(lessonRow("Found", "found", foundBits));
  if (f.attack) rows.push(lessonRow("The&nbsp;attack", "attack", esc(f.attack)));
  if (f.fix) rows.push(lessonRow("The&nbsp;fix", "fix", `<div class="fixbox">${esc(f.fix)}</div>`));
  if (f.learn) {
    const link = f.learnUrl ? ` <a href="${esc(f.learnUrl)}" target="_blank" rel="noopener">${esc(f.learnUrl.replace(/^https?:\/\//, "").split("/")[0])} →</a>` : "";
    rows.push(lessonRow("Learn", "learn", `<span class="muted">${esc(f.learn)}</span>${link}`));
  }

  return `<div class="card s-${band}">
    <div class="card-head">
      <span class="sev-badge">${esc(SEVERITY[f.severity]?.label || f.severity)}</span>
      <div class="card-title"><h3>${esc(f.title)}</h3><div class="scanner">scanner: ${esc(f.scanner)}</div></div>
      <div class="tags">${tags}</div>
    </div>
    <div class="card-body">${rows.join("")}</div>
  </div>`;
}

export function htmlReport(target, results, opts = {}) {
  const all = results.flatMap((r) => r.findings.map((f) => ({ ...f, scanner: r.scanner })))
    .filter((f) => f.severity !== "info")
    .sort((a, b) => SEVERITY[b.severity].rank - SEVERITY[a.severity].rank);

  const score = kaaliScore(all);
  const { letter, band } = letterGrade(score);
  const gradeColor = BAND_COLOR[band];
  const counts = ["critical", "high", "medium", "low"].map((s) => ({ s, n: all.filter((f) => f.severity === s).length }));

  // score ring geometry (r=54)
  const R = 54, CIRC = 2 * Math.PI * R;
  const offset = CIRC * (1 - score / 100);

  const prev = typeof opts.prevScore === "number" ? opts.prevScore : null;
  const trend = prev === null ? "" : (() => {
    const pg = letterGrade(prev), delta = score - prev;
    const up = delta >= 0;
    return `<div class="trend ${up ? "up" : "down"}">
      <span class="prev">${pg.letter} · ${prev}</span><span class="arrow">→</span>
      <span>${letter} · ${score}</span>
      <span class="delta">${up ? "▲" : "▼"} ${up ? "+" : ""}${delta} since last scan</span></div>`;
  })();

  const top3 = all.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 3);
  const fixFirst = top3.length ? `
    <div class="sec-head"><h2>Fix these first</h2><div class="rule"></div></div>
    <div class="priority">${top3.map((f, i) => `
      <div class="p-item">
        <div class="p-num">${i + 1}</div>
        <div class="p-text">${esc(f.title)}${f.attack ? `<div class="why">${esc(f.attack)}</div>` : ""}</div>
        <div class="p-sev s-${SEV_BAND[f.severity]}">${esc(f.severity)}</div>
      </div>`).join("")}</div>` : "";

  const cards = all.length
    ? `<div class="sec-head"><h2>What we found &amp; why it matters</h2><div class="rule"></div></div>
       <div class="cards">${all.map(cardHtml).join("")}</div>`
    : `<div class="clean">✓ No findings — clean for the checks that ran.</div>`;

  const verdict = all.length === 0
    ? "Clean — for the checks that ran."
    : band === "f" ? "Critical exposure. Start at the top."
    : band === "d" ? "At risk — the open doors below are the ones that get you."
    : band === "c" ? "Decent hygiene, real gaps remain."
    : "Solid — a few things left to tighten.";

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kaali Report Card — ${esc(target)}</title>
<style>
:root{--ground:#0A0E16;--panel:#111823;--panel-2:#17202E;--border:#253044;--border-soft:#1C2637;--text:#E7ECF4;--muted:#8794A6;--faint:#5C6879;--amber:#F6B24B;--crit:#FF5D5D;--high:#FF9D46;--med:#F1C84A;--low:#5AA9FF;--pass:#45D19A;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1100px 620px at 78% -8%,rgba(246,178,75,.07),transparent 60%),var(--ground);color:var(--text);font-family:var(--sans);-webkit-font-smoothing:antialiased;line-height:1.55}
.wrap{max-width:940px;margin:0 auto;padding:34px 22px 72px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding-bottom:20px;border-bottom:1px solid var(--border-soft)}
.brand{display:flex;align-items:center;gap:11px}
.brand-name{font-weight:700;letter-spacing:.04em;font-size:16px}
.brand-name b{color:var(--amber)}
.brand-sub{font-family:var(--mono);font-size:11px;color:var(--faint);margin-top:1px}
.target{text-align:right;font-family:var(--mono);font-size:12.5px;color:var(--muted)}
.target .host{color:var(--text);font-size:14px;word-break:break-all}
.target .ts{color:var(--faint);font-size:11px}
.grade-panel{margin-top:24px;display:grid;grid-template-columns:auto 1fr;gap:30px;align-items:center;background:linear-gradient(180deg,var(--panel-2),var(--panel));border:1px solid var(--border);border-radius:18px;padding:26px 28px}
.ring-slot{position:relative;width:132px;height:132px}
.ring-slot svg{transform:rotate(-90deg)}
.ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.grade-letter{font-family:var(--mono);font-size:48px;font-weight:700;line-height:1;letter-spacing:-.02em}
.grade-score{font-family:var(--mono);font-size:12px;color:var(--muted);margin-top:3px;font-variant-numeric:tabular-nums}
.verdict{font-size:21px;font-weight:650;letter-spacing:-.01em;margin:0 0 14px;text-wrap:balance}
.trend{display:inline-flex;align-items:center;gap:9px;font-family:var(--mono);font-size:12px;padding:5px 11px;border-radius:999px;margin-bottom:16px}
.trend.up{background:rgba(69,209,154,.09);border:1px solid rgba(69,209,154,.28);color:var(--pass)}
.trend.down{background:rgba(255,93,93,.09);border:1px solid rgba(255,93,93,.28);color:var(--crit)}
.trend .prev{color:var(--faint);text-decoration:line-through}
.trend .delta{color:var(--faint)}
.sev-row{display:flex;flex-wrap:wrap;gap:8px}
.chip{display:inline-flex;align-items:baseline;gap:6px;font-family:var(--mono);font-size:12px;padding:4px 10px;border-radius:7px;border:1px solid var(--border);background:var(--panel);font-variant-numeric:tabular-nums}
.chip b{font-size:13px}.chip .lbl{color:var(--muted)}
.chip.c-crit{border-color:rgba(255,93,93,.35)}.chip.c-crit b{color:var(--crit)}
.chip.c-high{border-color:rgba(255,157,70,.3)}.chip.c-high b{color:var(--high)}
.chip.c-med{border-color:rgba(241,200,74,.28)}.chip.c-med b{color:var(--med)}
.chip.c-low{border-color:rgba(90,169,255,.28)}.chip.c-low b{color:var(--low)}
.sec-head{display:flex;align-items:center;gap:12px;margin:42px 0 16px}
.sec-head h2{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin:0}
.sec-head .rule{height:1px;background:var(--border-soft);flex:1}
.priority{display:grid;gap:10px}
.p-item{display:grid;grid-template-columns:auto 1fr auto;gap:14px;align-items:center;background:var(--panel);border:1px solid var(--border-soft);border-left:3px solid var(--amber);border-radius:11px;padding:13px 16px}
.p-num{font-family:var(--mono);font-size:15px;font-weight:700;color:var(--amber);width:22px;text-align:center}
.p-text{font-size:14.5px}.p-text .why{color:var(--muted);font-size:13px}
.p-sev{font-family:var(--mono);font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;padding:3px 8px;border-radius:5px;white-space:nowrap}
.p-sev.s-crit{color:var(--crit);background:rgba(255,93,93,.1)}
.p-sev.s-high{color:var(--high);background:rgba(255,157,70,.1)}
.cards{display:grid;gap:16px}
.card{background:var(--panel);border:1px solid var(--border-soft);border-radius:13px;overflow:hidden;position:relative}
.card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.card.s-crit::before{background:var(--crit)}.card.s-high::before{background:var(--high)}
.card.s-med::before{background:var(--med)}.card.s-low::before{background:var(--low)}
.card-head{display:flex;align-items:flex-start;gap:12px;padding:16px 18px 14px 22px;flex-wrap:wrap}
.sev-badge{font-family:var(--mono);font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;padding:4px 9px;border-radius:6px;flex:none;margin-top:1px}
.s-crit .sev-badge{color:var(--crit);background:rgba(255,93,93,.12)}
.s-high .sev-badge{color:var(--high);background:rgba(255,157,70,.12)}
.s-med .sev-badge{color:var(--med);background:rgba(241,200,74,.12)}
.s-low .sev-badge{color:var(--low);background:rgba(90,169,255,.12)}
.card-title{flex:1;min-width:220px}
.card-title h3{margin:0;font-size:16.5px;font-weight:650;letter-spacing:-.01em}
.card-title .scanner{font-family:var(--mono);font-size:11.5px;color:var(--faint);margin-top:2px}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:2px}
.tag{font-family:var(--mono);font-size:10.5px;padding:3px 8px;border-radius:5px;border:1px solid var(--border)}
.tag.owasp{color:#C58BF0;border-color:rgba(197,139,240,.3);background:rgba(197,139,240,.06)}
.tag.dpdp{color:#5AC8D8;border-color:rgba(90,200,216,.3);background:rgba(90,200,216,.06)}
.card-body{padding:0 18px 18px 22px;display:grid;gap:12px}
.lesson{display:grid;grid-template-columns:74px 1fr;gap:14px;align-items:start;padding-top:12px;border-top:1px solid var(--border-soft)}
.lesson .k{font-family:var(--mono);font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);padding-top:2px}
.lesson .v{font-size:14px}.lesson .v .muted{color:var(--muted)}
.attack .v{color:#F3C7A6}
.evidence{display:inline-block;background:#0C1119;border:1px solid var(--border);border-radius:6px;padding:2px 8px;color:var(--muted);font-family:var(--mono);font-size:12.5px;word-break:break-all}
.fixbox{background:#0C1119;border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-family:var(--mono);font-size:12.5px;color:#CBE7D5;white-space:pre-wrap;overflow-x:auto;line-height:1.5}
.learn a{color:var(--low);text-decoration:none;border-bottom:1px solid rgba(90,169,255,.3)}
.learn a:hover{border-bottom-color:var(--low)}
.learn a:focus-visible{outline:2px solid var(--low);outline-offset:2px;border-radius:2px}
.clean{margin-top:24px;padding:22px;border:1px solid rgba(69,209,154,.3);background:rgba(69,209,154,.06);border-radius:13px;color:var(--pass);font-family:var(--mono)}
.foot{margin-top:46px;padding-top:20px;border-top:1px solid var(--border-soft);display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;font-family:var(--mono);font-size:11.5px;color:var(--faint)}
.foot .cmd b{color:var(--amber);font-weight:400}
@media(max-width:620px){.grade-panel{grid-template-columns:1fr;justify-items:center;text-align:center;gap:20px}.lesson{grid-template-columns:1fr;gap:4px}.lesson .k{padding-top:0}.p-item{grid-template-columns:auto 1fr}.p-sev{grid-column:2;justify-self:start}}
</style></head><body><div class="wrap">
  <div class="topbar">
    <div class="brand">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M9 3h6M12 3v2" stroke="#F6B24B" stroke-width="1.6" stroke-linecap="round"/>
        <rect x="7" y="6" width="10" height="13" rx="2.4" stroke="#F6B24B" stroke-width="1.6"/>
        <circle cx="12" cy="12.5" r="3" fill="#F6B24B" fill-opacity="0.9"/>
        <path d="M8 21h8" stroke="#F6B24B" stroke-width="1.6" stroke-linecap="round"/></svg>
      <div><div class="brand-name">V<b>i</b>GIL</div><div class="brand-sub">security report card</div></div>
    </div>
    <div class="target"><div class="host">${esc(target)}</div><div class="ts">scanned ${new Date().toISOString().replace("T", " ").slice(0, 16)} UTC · ${results.length} scanners</div></div>
  </div>
  <div class="grade-panel">
    <div class="ring-slot">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle cx="66" cy="66" r="${R}" fill="none" stroke="#1C2637" stroke-width="11"/>
        <circle cx="66" cy="66" r="${R}" fill="none" stroke="${gradeColor}" stroke-width="11" stroke-linecap="round" stroke-dasharray="${CIRC.toFixed(1)}" stroke-dashoffset="${offset.toFixed(1)}"/>
      </svg>
      <div class="ring-center"><div class="grade-letter" style="color:${gradeColor}">${letter}</div><div class="grade-score">${score} / 100</div></div>
    </div>
    <div class="grade-info">
      <p class="verdict">${esc(verdict)}</p>
      ${trend}
      <div class="sev-row">${counts.map((x) => `<span class="chip c-${SEV_BAND[x.s]}"><b>${x.n}</b><span class="lbl">${x.s}</span></span>`).join("")}</div>
    </div>
  </div>
  ${fixFirst}
  ${cards}
  <div class="foot">
    <div class="cmd">$ npx <b>@kaali/cli</b> scan ${esc(target)} --html</div>
    <div>Kaali v0.1 · report card</div>
  </div>
</div></body></html>`;
}
