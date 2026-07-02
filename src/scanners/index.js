import * as web from "./web-headers.js";
import * as secrets from "./secrets.js";
import * as pii from "./pii-dpdp.js";
import * as content from "./poisoned-content.js";
import * as ai from "./prompt-injection.js";
import * as aiIndirect from "./indirect-injection.js";
import * as mcp from "./mcp.js";
import * as mcpDiscover from "./mcp-discover.js";

// Registry. Order = display order. `applies(target)` decides auto-run;
// opt-in scanners (ai, ai-indirect, mcp, mcp-discover) are enabled by flags.
export const SCANNERS = [web, content, secrets, pii, ai, aiIndirect, mcp, mcpDiscover];

export function byId(id) {
  return SCANNERS.find((s) => s.meta.id === id);
}
