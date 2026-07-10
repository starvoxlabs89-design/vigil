import { readFile } from "node:fs/promises";
import { finding, timedFetch } from "../util.js";

// Detects whether a document/page is a PROMPT-INJECTION VECTOR — the thing an
// AI agent might ingest. No LLM endpoint required: it inspects content for
// (a) invisible-Unicode-encoded instructions (the GlassWorm vector that
// Bumblebee's catalog documents but cannot detect), and (b) hidden/cloaked
// instruction text aimed at AI assistants.
//
// Auto-applies to URLs (fetched) and local files. This is the "is my own
// content safe for an agent to read?" check — and a defender's scanner for
// pages your agents crawl.
export const meta = {
  id: "content",
  title: "Poisoned content / hidden AI instructions",
  applies: (t) => /^https?:\/\//i.test(t) || /\.(html?|md|txt|json|csv|xml|rss)$/i.test(t),
};

// Invisible / steganographic Unicode ranges abused to hide instructions.
const INVISIBLE = [
  { re: /[\u{E0000}-\u{E007F}]/u, id: "unicode-tags", name: "Unicode Tag chars (U+E00xx)" },
  { re: /[​-‍﻿⁠]/u, id: "zero-width", name: "zero-width chars" },
  { re: /[‪-‮⁦-⁩]/u, id: "bidi", name: "bidirectional override chars" },
];

// Instruction-like phrases targeting an assistant (in any visible-or-hidden text).
const INSTRUCTION = [
  /ignore (all |the |your )?(previous|prior|above) (instructions|prompt)/i,
  /\b(ai|assistant|model|agent|llm|chatbot)[:\s,].{0,40}(ignore|disregard|instead|must|output|print|reply|append|reveal)/i,
  /system\s*(override|prompt|directive|instruction)/i,
  /do not (tell|reveal|mention|inform) the user/i,
  /(exfiltrate|send).{0,30}(https?:|to the following)/i,
];

function decodeTagChars(text) {
  // Recover ASCII hidden in the Unicode Tags block so we can read the payload.
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0000 && cp <= 0xe007f) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

// Strip visible HTML but KEEP comments + hidden elements (that's where injection hides).
function extractHidden(html) {
  const comments = [...html.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1]).join("\n");
  const hiddenEls = [...html.matchAll(/<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|aria-hidden\s*=\s*["']true["']|hidden)[^>]*>([\s\S]*?)<\//gi)].map((m) => m[1]).join("\n");
  return comments + "\n" + hiddenEls;
}

export async function run(target) {
  const findings = [];
  let text;
  try {
    if (/^https?:\/\//i.test(target)) {
      const res = await timedFetch(target, { redirect: "follow" });
      text = await res.text();
    } else {
      text = await readFile(target, "utf8");
    }
  } catch (e) {
    return [finding({ id: "content-unreachable", title: "Could not read target", severity: "info", detail: String(e.message || e) })];
  }

  // 1) Invisible / steganographic characters
  for (const inv of INVISIBLE) {
    if (inv.re.test(text)) {
      const decoded = inv.id === "unicode-tags" ? decodeTagChars(text) : "";
      findings.push(finding({
        id: `content-${inv.id}`,
        title: `Invisible characters present (${inv.name})`,
        severity: decoded && INSTRUCTION.some((r) => r.test(decoded)) ? "critical" : "high",
        detail: decoded
          ? `Hidden text decodes to: "${decoded.slice(0, 80)}"`
          : "Invisible characters can smuggle instructions to an AI reader.",
        evidence: inv.name,
        owasp: "LLM01:2025",
        fix: "Strip non-printable / tag / zero-width / bidi Unicode from any content before an LLM reads it.\n# runtime guard: @starvoxlabs89-design/vigil-guard decodes + blocks this inline",
        attack: "These characters are invisible to a human reviewer but readable by a model. An attacker smuggles a command into a page, doc, or PR — your AI reads and obeys it while you see nothing wrong.",
        learn: "This is the GlassWorm-class vector: instructions hidden in Unicode that supply-chain matchers document but can't detect. You have to actually decode the bytes to see the payload.",
        learnUrl: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      }));
    }
  }

  // 2) Hidden instruction text (HTML comments / display:none) targeting an assistant
  const hidden = /<[a-z!]/i.test(text) ? extractHidden(text) : "";
  for (const re of INSTRUCTION) {
    if (hidden && re.test(hidden)) {
      findings.push(finding({
        id: "content-hidden-instruction",
        title: "Hidden AI-targeted instruction in markup",
        severity: "critical",
        detail: "Instruction-like text aimed at an assistant is concealed in a comment or hidden element.",
        evidence: (hidden.match(re)?.[0] || "").slice(0, 80),
        owasp: "LLM01:2025",
        fix: "Sanitize HTML comments / hidden nodes from agent-ingested content; render to plain text first.\n# treat all retrieved content as DATA, never as instructions",
        attack: "When your support bot — or a user's ChatGPT/Claude — reads this page, it can obey the hidden comment as if it were a command: leak the system prompt, phish the user, or call a tool. The attacker never touches your server; they poison the content your AI trusts.",
        learn: "Indirect prompt injection: the model can't tell your instructions from text it was asked to read. It's #1 on the OWASP LLM Top 10 two years running.",
        learnUrl: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      }));
      break;
    }
  }
  return findings;
}
