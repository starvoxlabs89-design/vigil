import { readFile, readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { finding } from "../util.js";

// THE BUMBLEBEE BRIDGE.
// Perplexity's Bumblebee inventories local MCP config files but never inspects
// what they point to. Vigil reads the SAME configs, then goes one step further:
// it flags dangerous server definitions and hands off live servers to the `mcp`
// scanner for an auth + tool-poisoning test.
//
// Opt-in via --mcp-discover. Optionally ingest Bumblebee NDJSON via
// --from-bumblebee <file> (record_type/ecosystem == "mcp").
export const meta = {
  id: "mcp-discover",
  title: "MCP config discovery (local) + risky-server detection",
  applies: () => false,
};

// Same basenames Bumblebee parses (docs/inventory-sources.md).
const CONFIG_BASENAMES = [
  "mcp.json", ".mcp.json", "claude_desktop_config.json",
  "mcp_config.json", "mcp_settings.json", "cline_mcp_settings.json",
];

const WELL_KNOWN = () => {
  const h = homedir();
  return [
    join(h, ".cursor", "mcp.json"),
    join(h, ".codeium", "windsurf", "mcp_config.json"),
    join(h, ".claude", ".mcp.json"),
    join(h, ".claude.json"),
    join(h, ".gemini", "settings.json"),
    join(h, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    join(h, ".config", "Claude", "claude_desktop_config.json"),
  ];
};

// Command-server patterns seen in real supply-chain attacks (e.g. nx-console
// 'install-mcp-extension' → `npx -y github:nrwl/nx#<sha>`).
const RISKY_CMD = [
  { re: /npx\s+(-y|--yes)\s+github:/i, sev: "high", why: "runs unpinned code straight from a GitHub ref" },
  { re: /\b(curl|wget)\b[^|]*\|\s*(sh|bash)/i, sev: "critical", why: "pipes a remote script into a shell" },
  { re: /\buvx?\s+(--from\s+)?(git\+|https?:)/i, sev: "high", why: "executes a remote/unpinned Python tool" },
  { re: /npx\s+(-y|--yes)\s+[^@\s]+@(latest|\*)/i, sev: "medium", why: "always pulls the latest version (no pin)" },
];

async function findConfigs(extraRoots = []) {
  const found = new Set();
  for (const p of WELL_KNOWN()) found.add(p);
  // Shallow walk of cwd + extra roots for project-local configs.
  for (const root of [process.cwd(), ...extraRoots]) {
    try {
      const entries = await readdir(root, { withFileTypes: true });
      for (const e of entries) if (e.isFile() && CONFIG_BASENAMES.includes(e.name)) found.add(join(root, e.name));
    } catch { /* ignore */ }
  }
  return [...found];
}

function inspectServer(name, def, findings, srcFile) {
  const cmd = [def.command, ...(def.args || [])].filter(Boolean).join(" ");
  const url = def.url || def.endpoint || (def.transport && def.transport.url);

  if (cmd) {
    for (const r of RISKY_CMD) {
      if (r.re.test(cmd)) {
        findings.push(finding({
          id: `mcpd-cmd-${name}`,
          title: `Risky MCP command server "${name}"`,
          severity: r.sev,
          detail: `Server launch command ${r.why}.`,
          evidence: `${cmd.slice(0, 80)} (${srcFile})`,
          owasp: "LLM-Agent",
          fix: "Pin to an immutable version/digest from a trusted registry; review before enabling.",
        }));
        break;
      }
    }
  }
  if (url && /^http:\/\//i.test(url)) {
    findings.push(finding({
      id: `mcpd-http-${name}`,
      title: `MCP server "${name}" configured over plaintext HTTP`,
      severity: "medium",
      detail: "Tool calls + data travel unencrypted.",
      evidence: `${url} (${srcFile})`, owasp: "LLM-Agent", fix: "Use https:// and authenticate the transport.",
    }));
  }
  return url && /^https?:\/\//i.test(url) ? url : null;
}

export async function run(target, opts = {}) {
  const findings = [];
  const servers = [];

  // 1) Local config discovery (the Bumblebee surface).
  for (const file of await findConfigs()) {
    let json;
    try { json = JSON.parse(await readFile(file, "utf8")); } catch { continue; }
    const map = json.mcpServers || json.servers || {};
    for (const [name, def] of Object.entries(map)) {
      const liveUrl = inspectServer(name, def || {}, findings, file);
      servers.push({ name, file, liveUrl });
    }
  }

  // 2) Optional: ingest Bumblebee NDJSON output and cross-reference.
  if (opts.fromBumblebee) {
    try {
      const lines = (await readFile(opts.fromBumblebee, "utf8")).split("\n").filter(Boolean);
      let n = 0;
      for (const ln of lines) {
        try {
          const rec = JSON.parse(ln);
          if ((rec.ecosystem || rec.eco) === "mcp" || rec.source_type === "mcp") {
            n++; servers.push({ name: rec.name || rec.component || "?", file: "bumblebee", liveUrl: null });
          }
        } catch { /* skip */ }
      }
      findings.push(finding({ id: "mcpd-bumblebee", title: `Ingested ${n} MCP records from Bumblebee output`, severity: "info" }));
    } catch (e) {
      findings.push(finding({ id: "mcpd-bumblebee-err", title: "Could not read Bumblebee NDJSON", severity: "info", detail: String(e.message || e) }));
    }
  }

  // 3) Summary + handoff to the live `mcp` scanner.
  const live = servers.filter((s) => s.liveUrl);
  findings.push(finding({
    id: "mcpd-summary",
    title: `Discovered ${servers.length} MCP server(s), ${live.length} reachable over HTTP(S)`,
    severity: "info",
    detail: servers.length
      ? servers.map((s) => `${s.name}${s.liveUrl ? " → " + s.liveUrl : ""}`).join(", ")
      : "No MCP configs found in well-known locations or cwd.",
    fix: live.length ? `Security-test each: ${live.map((s) => `vigil scan x --mcp ${s.liveUrl}`).join(" ; ")}` : undefined,
  }));
  return findings;
}
