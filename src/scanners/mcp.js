import { finding, timedFetch } from "../util.js";

// Checks an MCP (Model Context Protocol) server endpoint for the two issues
// flagged by NSA/Trend Micro in 2026: exposed-with-no-auth, and tool-poisoning
// (hidden/suspicious instructions inside tool descriptions).
export const meta = {
  id: "mcp",
  title: "MCP server exposure & tool poisoning",
  applies: () => false, // opt-in via --mcp <url>
};

const POISON_HINTS = [
  /ignore (all|previous|the above)/i,
  /system prompt/i,
  /do not (tell|reveal|mention)/i,
  /exfiltrate|send .* to https?:/i,
  /<important>|<secret>|\bhidden\b/i,
];

export async function run(target, opts = {}) {
  const url = opts.mcpUrl || target;
  const findings = [];

  // 1) Is it reachable with no auth? Try a tools/list JSON-RPC call.
  let listText = "";
  try {
    const res = await timedFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    }, 15000);
    listText = await res.text();
    if (res.status === 200 && /"tools"|"name"/.test(listText)) {
      findings.push(finding({
        id: "mcp-no-auth", title: "MCP server responds with no authentication", severity: "critical",
        detail: "tools/list returned data without credentials.",
        owasp: "LLM-Agent", fix: "Require auth (OAuth/session binding) before tools/list; bind tokens to session identity.",
      }));
    }
  } catch (e) {
    return [finding({ id: "mcp-unreachable", title: "MCP endpoint unreachable", severity: "info", detail: String(e.message || e) })];
  }

  // 2) Tool-description poisoning — scan descriptions for hidden instructions.
  try {
    const parsed = JSON.parse(listText);
    const tools = parsed?.result?.tools || parsed?.tools || [];
    for (const tool of tools) {
      const desc = `${tool.description || ""} ${JSON.stringify(tool.inputSchema || {})}`;
      for (const re of POISON_HINTS) {
        if (re.test(desc)) {
          findings.push(finding({
            id: `mcp-poison-${tool.name || "tool"}`,
            title: `Possible tool poisoning in "${tool.name}"`,
            severity: "high",
            detail: "Tool metadata contains instruction-like / hidden directives the model would read.",
            evidence: desc.slice(0, 80) + "…",
            owasp: "LLM-Agent",
            fix: "Treat tool descriptions as untrusted; sign tool manifests; review on registration.",
          }));
          break;
        }
      }
    }
  } catch {
    // non-JSON response; nothing to parse
  }
  return findings;
}
