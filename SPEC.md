# Kaali — Product Spec (v0.1)

> Working name. Rename is trivial (one string in `package.json`). Candidates if "Kaali" collides: **Kavach**, **Prahari**, **Drishti** (India-flavored), or **Sentry/Argus** alternatives. Check npm + GitHub + trademark before locking.

## 1. One-liner

Open-source, developer-first security scanner that — in one command — finds the things AI-era apps leak (prompt injection, exposed MCP servers, hardcoded secrets, Indian PII/DPDP exposure, weak web posture) and produces a shareable score; the hosted tier turns the same engine into **24/7 monitoring + the DPDP/ISO-42001 evidence report**.

## 2. The wedge (why this, why now)

- **The AI-security OSS leader is orphaned.** `protectai/llm-guard` hasn't shipped since Dec 2025 (Palo Alto acquisition). Lakera→Check Point, CalypsoAI→F5. The independent OSS lane is empty.
- **Observability ≠ security.** Langfuse (29.7k★), OpenLIT, OpenLLMetry watch cost/quality/latency. None watch prompt injection, agent privilege abuse, MCP poisoning, or PII leakage in live traffic.
- **Uptime & web-vuln are solved/free.** Uptime Kuma (88k★), ZAP (15k★), Nuclei (29k★) own those. Don't compete there — *complement* them.
- **DPDP is a budgeted, dated trigger.** Rules notified Nov 2025; hard enforcement **May 13–14, 2027**; penalties to ₹250 crore. No AI-security tool is DPDP-native. This is the unfair-advantage zone (ties to Trst/Sentra).

## 2b. Competitive positioning (adversarially verified, June 2026)

A deep-research pass (104 agents, 24/25 claims verified) stress-tested the differentiation. Verdict: **real, but only at a precise 4-way intersection.** Each axis alone is contested or owned.

**Confirmed open ground:**
- **Bumblebee is adjacent, not a competitor** (verified 3-0). Read-only, one-shot, on-disk inventory collector; only *parses* local MCP config files; "no process or network monitoring — not an EDR." Its scope ends where a runtime-app scanner begins.
- **DPDP-evidence-for-AI-apps is unclaimed.** KavachOne et al. scan only data-at-rest (DBs/buckets/files) — zero AI/LLM/MCP/runtime coverage.
- **Continuous monitoring of DEPLOYED MCP servers is open.** Cisco MCP Scanner (Apache-2.0, ~971★, Dec 2025) is explicitly *pre-deployment/CI*; Cisco walls runtime into closed AI Defense. Real risk is minority-but-measurable (Hasan et al.: 5.5% tool-poisoning across 1,899 servers).
- **Runtime AI security validated but going closed/enterprise.** Lakera → Check Point (~Sept 2025, ~$300M), continuous but closed. OSS + dev-first is the contested ground.

**MUST NOT overclaim (these are FALSE — flagged by the research):**
1. ❌ "First/only DPDP-native PII scanner" — KavachOne, dcomply, Complynz, Securiti, Protecto, Privy/IDfy already own data-at-rest Indian PII + DPDP reports. **Also kills "Kavach" as a name (collides with KavachOne).**
2. ❌ "First runtime AI security" — Lakera exists.
3. ❌ Competing on supply-chain / SCA / SAST — saturated (Endor Labs $70M Series A, Socket ~$1B, Chainguard, Snyk, Trivy). Suicidal for a small founder.

**The only defensible claim — the 4-way intersection:**
> open-source **+** developer-first **+** continuous runtime AI/agent security (incl. **deployed** MCP) **+** DPDP evidence for the AI app itself.

**Research caveats:** several competitor facts rest on vendor PR (Lakera metrics, KavachOne accuracy unverified); the ~78% MCP false-positive figure is one small 33-server study — do not generalize; per-vendor funding/OSS-staleness for most runtime-AI competitors not individually re-verified. Re-check Bumblebee/Cisco scope before publishing a public comparison — both are fast-moving.

## 3. Moat (the durable stack — copyable in pieces, not as a whole)

1. **Proprietary attack-data flywheel.** Every prompt-injection probe result, every novel jailbreak, every poisoned MCP tool seen across users → a dataset competitors can't buy. The detection rules commoditize; the *corpus* compounds. **Build the company around this.**
2. **Developer distribution.** Become the default `npx` tool in CI pipelines and muscle memory (the promptfoo/Trivy playbook). Sticky even against feature-clones.
3. **Compliance artifact lock-in.** Be the named tool that emits the **DPDP / ISO-42001 / OWASP-LLM evidence report** an auditor accepts. Auditor trust is slow to copy.

## 4. Architecture

```
                      ┌─────────────────────────────────────┐
   kaali (OSS CLI)    │  bin/kaali.js → src/cli.js           │
   ─ zero-dep, MIT ─  │     ├─ scanners/  (pluggable)        │
                      │     │    web · secrets · pii · ai ·  │
                      │     │    mcp  (+ community probes)    │
                      │     ├─ report.js (terminal/JSON/SARIF)│
                      │     └─ util.js   (severity, score)    │
                      └──────────────┬──────────────────────┘
                                     │  --report → POST (opt-in telemetry)
                                     ▼
                      ┌─────────────────────────────────────┐
   Kaali Cloud (paid) │  Ingest (OTEL-native) → Timescale DB │
                      │  ├─ 24/7 monitor (interval re-scan)  │
                      │  ├─ live LLM/agent traffic guardrail │
                      │  ├─ trends · diff · alerting (Slack)  │
                      │  ├─ attack-data flywheel (the moat)  │
                      │  └─ DPDP/ISO-42001 evidence report   │
                      └─────────────────────────────────────┘
```

**Design decisions made in v0.1:**
- **Zero dependencies** (Node ≥20 built-in `fetch`) → clone-and-run, no supply-chain risk, instant `npx`.
- **Pluggable scanner registry** (`src/scanners/index.js`) → community PRs add probes = community-driven coverage growth (a soft moat).
- **OTEL as the ingestion standard** for Cloud → ride the industry convergence, plug into Datadog/Honeycomb, avoid lock-in objections.
- **Severity-weighted Kaali Score** → the shareable, viral artifact (people screenshot scores).

## 5. OSS vs. Paid line (the bridge)

| | Free / OSS (the wedge) | Kaali Cloud (the revenue) |
|---|---|---|
| Scan engine (all 5 scanners) | ✅ local, unlimited | ✅ |
| Kaali Score + fixes | ✅ | ✅ |
| CI/CD `--fail-on` gate | ✅ | ✅ |
| **24/7 continuous monitoring** | — | ✅ interval re-scan + live traffic |
| History, trends, diff over time | — | ✅ |
| Alerting (Slack/email/webhook) | — | ✅ |
| Multi-target / team dashboard, SSO/RBAC | — | ✅ |
| **DPDP / ISO-42001 / OWASP-LLM evidence report (PDF)** | — | ✅ ← the enterprise hook |
| Managed threat-intel rule updates | basic | ✅ premium corpus |

Free tool collects the data + the inbound; paid tier is the team-of-record + the artifact a regulator accepts.

## 6. The "24/7 monitoring" build (what `kaali monitor` becomes)

1. **Scheduled re-scan** of registered targets (cron/interval), storing each run.
2. **Diff engine** — alert only on *new* findings (no alert fatigue).
3. **Live runtime mode** — a lightweight middleware/SDK + OTEL collector that inspects LLM/agent traffic in production for injection, PII egress, and anomalous tool calls (the continuous analogue of the `ai`/`mcp` scanners).
4. **Alerting + status page** — Slack/webhook on regressions; public/private posture page.
5. **Evidence rollup** — continuous monitoring *is* the audit evidence; the report writes itself.

## 7. Viral launch plan (bottom-up)

- **Hook:** `npx kaali scan <your-site>` → instant scary score. The DPDP/Aadhaar angle is novel and India-press-friendly.
- **Channels:** Show HN ("Kaali — the security scanner for AI apps, in one command"); r/netsec, r/devops; a sharp launch thread in operator voice; PH.
- **Content flywheel:** publish anonymized aggregate findings ("we scanned 1,000 Indian SaaS sites — X% leak PAN numbers in their JS") → press + backlinks + the data moat made visible.
- **Stars→revenue:** seed CI/CD adoption → "monitor this 24/7?" upsell → DPDP report closes enterprise.

## 8. Status (v0.1 — built this session)

- ✅ CLI (`scan`, `list`, `monitor` stub, `--json`, `--fail-on`, `--only`, `--ai`, `--mcp`)
- ✅ `web` scanner — live header/TLS/disclosure checks (tested vs example.com)
- ✅ `secrets` scanner — multi-provider key + private-key detection (tested)
- ✅ `pii` scanner — Aadhaar (Verhoeff-validated), PAN, mobile, email → DPDP tags (tested)
- ✅ `ai` scanner — 4 prompt-injection canary probes (opt-in, needs live endpoint)
- ✅ `mcp` scanner — no-auth exposure + tool-poisoning heuristics (opt-in, needs live endpoint)
- ✅ Kaali Score + severity-ranked terminal/JSON report

## 9. Next slices (priority order)

1. SARIF output (GitHub code-scanning integration → free distribution).
2. GitHub Action wrapper (`kaali-action`) → one-line adoption in any repo.
3. More `secrets` providers + entropy detection; `web` → light DAST (Nuclei-template ingestion).
4. Real MCP transport support (SSE/streamable-HTTP) + signed-manifest check.
5. `ai` config file (custom endpoints, auth, response-shape mapping) + jailbreak corpus.
6. Cloud MVP: hosted scan + interval monitor + Slack alert + first DPDP PDF.
7. Anonymized aggregate-findings dataset → content + moat.
