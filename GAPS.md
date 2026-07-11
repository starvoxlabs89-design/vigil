# Bumblebee — study & gap analysis

Source studied: `github.com/perplexityai/bumblebee` (cloned & read, June 2026 — README, `docs/inventory-sources.md`, `docs/state-model.md`, `threat_intel/*.json`, `internal/scanner`, JSON schemas).

## What Bumblebee actually is (from the code, not the PR)

A **read-only, known-bad *matcher* for a developer's machine.** Pipeline:

```
walk on-disk metadata  →  emit NDJSON component records  →  exact-match
(lockfiles, pkg meta,      (record_type=package-record)     (ecosystem,name,version)
 extension manifests,                                        against --exposure-catalog
 MCP JSON configs)                                           (hand-curated threat intel)
```

- **Pure exact-match.** Even the rich behavioral/network IOCs in its own catalogs are, in their words, *"not consumed by the scanner"* — analyst context only.
- **Threat-intel = curated data.** Catalogs (GlassWorm, Shai-Hulud, nx-console, etc.) are built from Socket/StepSecurity advisories via "Perplexity Computer" and merged by PR. Also generatable from an OSV snapshot, offline.
- **MCP = config *inventory* only.** Parses `mcp.json`/`claude_desktop_config.json`/etc. for the server list; reduces remote URLs to `scheme://host`; does **not** emit `env` creds. Never connects.
- **Snapshot-only.** No delta DB, one-shot, promote-on-complete-summary. macOS/Linux. Go 1.25+, zero non-stdlib deps, single static binary.

**Verdict:** excellent at its narrow job — "which of my machines match a published advisory *right now*." Read-only safety model is genuinely well-designed and trust-building.

## The seams it leaves open (where Kaali plays)

| # | Bumblebee gap | Why it matters | Kaali answer |
|---|---|---|---|
| 1 | **MCP = inventory only.** Reads configs, never tests servers. | It *sees* every MCP server you use and does nothing security-wise. | `mcp` (deployed-server auth + tool-poisoning) + `mcp-discover` (reads the **same** configs, flags risky launch commands, hands off to live test) |
| 2 | **Reactive matcher, zero discovery.** No advisory = invisible. | Can't find anything novel/zero-day, only catalogued IOCs. | Kaali *probes for behaviour* (injection, exposure), not version strings — finds the unknown. |
| 3 | **Inventory ≠ vulnerability.** Lists components; never asks "is it exploitable?" | A clean version list says nothing about runtime risk. | Active probes return exploitability, not presence. |
| 4 | **Blind to invisible-Unicode.** Its GlassWorm catalog *documents* the invisible-loader vector but only version-matches it. | The actual attack content goes undetected. | `content` scanner **decodes** U+E00xx tag chars + zero-width/bidi and reads the hidden instruction. |
| 5 | **No AI-app security.** Despite reading MCP configs, zero prompt-injection / agent testing. | The #1 OWASP-LLM risk is untouched. | `ai` (direct) + `ai-indirect` (poisoned retrieved content) probes. |
| 6 | **No PII / DPDP.** | India compliance trigger ignored. | `pii` (Aadhaar Verhoeff + PAN) in code/logs/LLM output. |
| 7 | **Dev-machine, not shipped app.** Scans your laptop, not your deployed service. | Production attack surface unscanned. | Kaali targets URLs + endpoints + deployed MCP. |
| 8 | **One-shot, no runtime.** | No continuous monitoring. | Kaali Cloud = 24/7 re-scan + runtime stream (roadmap). |

## What we COPIED from Bumblebee (good ideas, adopted)

- **"Looks without touching" read-only discipline** → our static scanners (`secrets`, `pii`, `content`) never execute target code; we advertise the same safety guarantee.
- **Threat-intel-as-PR-updatable-data** → roadmap: a `catalog/` of known injection payloads, malicious MCP servers, and risky launch patterns, community-PR'd (a distribution + moat play, exactly like their catalogs).
- **NDJSON + JSON-schema output contract** → our `--json` + future Cloud ingest mirror this.
- **Scan profiles & zero-dep single-artifact discipline** → already zero-dependency; profiles on roadmap.

## The integration story (the headline)

> **Bumblebee tells you which MCP servers you have. Kaali tells you which ones are dangerous.**

Literal interop: `bumblebee ... > inv.ndjson` → `kaali scan x --mcp-discover --from-bumblebee inv.ndjson`. We consume their inventory and security-test it. Complementary, not competitive — we start exactly where they stop.

## New in this build (all tested)

- `content` — invisible-Unicode + hidden-instruction detector (no endpoint needed). **The thing Bumblebee structurally can't do.**
- `ai-indirect` — indirect prompt injection via poisoned web-page / tool-result / email / invisible-unicode vectors (Greshake et al., arXiv:2302.12173).
- `mcp-discover` — local MCP config discovery + risky-server detection + Bumblebee NDJSON ingest.
