import { finding, timedFetch } from "../util.js";

// Checks a live URL for missing/weak security headers + info leakage.
// Maps to OWASP ASVS / common web-app hygiene.
export const meta = {
  id: "web",
  title: "Web security headers & exposure",
  applies: (t) => /^https?:\/\//i.test(t),
};

const CHECKS = [
  { header: "strict-transport-security", sev: "medium", title: "Missing HSTS", fix: "Add Strict-Transport-Security: max-age=63072000; includeSubDomains" },
  { header: "content-security-policy", sev: "medium", title: "Missing Content-Security-Policy", fix: "Define a CSP to mitigate XSS / data injection" },
  { header: "x-frame-options", sev: "low", title: "Missing X-Frame-Options", fix: "Set X-Frame-Options: DENY (or use CSP frame-ancestors)" },
  { header: "x-content-type-options", sev: "low", title: "Missing X-Content-Type-Options", fix: "Set X-Content-Type-Options: nosniff" },
  { header: "referrer-policy", sev: "info", title: "Missing Referrer-Policy", fix: "Set Referrer-Policy: strict-origin-when-cross-origin" },
];

export async function run(target) {
  const findings = [];
  let res;
  try {
    res = await timedFetch(target, { redirect: "follow" });
  } catch (e) {
    return [finding({ id: "web-unreachable", title: "Target unreachable", severity: "info", detail: String(e.message || e) })];
  }
  const h = res.headers;

  for (const ch of CHECKS) {
    if (!h.get(ch.header)) {
      findings.push(finding({ id: `web-${ch.header}`, title: ch.title, severity: ch.sev, fix: ch.fix, owasp: "OWASP-Web" }));
    }
  }

  // Server / framework version disclosure
  for (const leak of ["server", "x-powered-by", "x-aspnet-version"]) {
    const v = h.get(leak);
    if (v && /[0-9]/.test(v)) {
      findings.push(finding({
        id: `web-leak-${leak}`, title: `Version disclosure via ${leak}`, severity: "low",
        evidence: `${leak}: ${v}`, fix: `Strip or obfuscate the ${leak} header`, owasp: "OWASP-Web",
      }));
    }
  }

  // Plain HTTP (no TLS) — DPDP-relevant for personal data in transit
  if (target.startsWith("http://")) {
    findings.push(finding({
      id: "web-no-tls", title: "Served over plaintext HTTP", severity: "high",
      detail: "Personal data in transit is unencrypted.", dpdp: "reasonable-security-safeguards",
      fix: "Force HTTPS and redirect all HTTP traffic.",
    }));
  }
  return findings;
}
