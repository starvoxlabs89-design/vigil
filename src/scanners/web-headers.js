import { finding, timedFetch } from "../util.js";

// Checks a live URL for missing/weak security headers + info leakage.
// Maps to OWASP ASVS / common web-app hygiene.
export const meta = {
  id: "web",
  title: "Web security headers & exposure",
  applies: (t) => /^https?:\/\//i.test(t),
};

const CHECKS = [
  {
    header: "strict-transport-security", sev: "medium", title: "Missing HSTS",
    fix: "Add Strict-Transport-Security: max-age=63072000; includeSubDomains",
    attack: "The first request a browser makes can still go over plain HTTP — an attacker on the same network downgrades it and reads the session before HTTPS kicks in.",
    learn: "HSTS tells browsers to only ever talk to you over HTTPS, closing the downgrade window.",
    learnUrl: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
  },
  {
    header: "content-security-policy", sev: "medium", title: "Missing Content-Security-Policy",
    fix: "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\n# start in Report-Only, watch violations, then enforce",
    attack: "If one XSS slips in — a comment field, a third-party script — there's nothing to stop injected JavaScript from stealing session tokens or rewriting your checkout page.",
    learn: "CSP won't stop XSS from existing — it caps what an injected script is allowed to do. Defense in depth, not a silver bullet.",
    learnUrl: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
  },
  {
    header: "x-frame-options", sev: "low", title: "Missing X-Frame-Options",
    fix: "Set X-Frame-Options: DENY (or use CSP frame-ancestors 'none')",
    attack: "An attacker embeds your page invisibly in their own and tricks users into clicking real buttons on your site — clickjacking a payment or a settings change.",
    learn: "Framing controls stop your UI being weaponised inside someone else's page.",
    learnUrl: "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
  },
  {
    header: "x-content-type-options", sev: "low", title: "Missing X-Content-Type-Options",
    fix: "Set X-Content-Type-Options: nosniff",
    attack: "Browsers guess ('sniff') content types — an uploaded image can be re-interpreted as a script and executed.",
    learn: "'nosniff' forces the browser to trust your declared Content-Type instead of guessing.",
    learnUrl: "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
  },
  {
    header: "referrer-policy", sev: "info", title: "Missing Referrer-Policy",
    fix: "Set Referrer-Policy: strict-origin-when-cross-origin",
    attack: "Full URLs (which may carry tokens or IDs) leak to every third-party site your pages link out to.",
    learn: "A referrer policy trims what leaves your origin in the Referer header.",
    learnUrl: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
  },
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
      findings.push(finding({
        id: `web-${ch.header}`, title: ch.title, severity: ch.sev, fix: ch.fix, owasp: "OWASP-Web",
        attack: ch.attack, learn: ch.learn, learnUrl: ch.learnUrl,
      }));
    }
  }

  // Server / framework version disclosure
  for (const leak of ["server", "x-powered-by", "x-aspnet-version"]) {
    const v = h.get(leak);
    if (v && /[0-9]/.test(v)) {
      findings.push(finding({
        id: `web-leak-${leak}`, title: `Version disclosure via ${leak}`, severity: "low",
        evidence: `${leak}: ${v}`, fix: `Strip or obfuscate the ${leak} header`, owasp: "OWASP-Web",
        attack: `You're broadcasting exactly what software and version you run (${v}). An attacker skips reconnaissance and looks up known CVEs for that exact build.`,
        learn: "Version banners turn a targeted attack into a lookup. Suppressing them buys time and raises the effort bar.",
        learnUrl: "https://owasp.org/www-project-secure-headers/",
      }));
    }
  }

  // Plain HTTP (no TLS) — DPDP-relevant for personal data in transit
  if (target.startsWith("http://")) {
    findings.push(finding({
      id: "web-no-tls", title: "Served over plaintext HTTP", severity: "high",
      detail: "Personal data in transit is unencrypted.", dpdp: "reasonable-security-safeguards",
      fix: "Force HTTPS and redirect all HTTP traffic; add HSTS once stable.",
      attack: "Anyone between your user and your server — café Wi-Fi, a rogue router, an ISP — reads and rewrites every request in the clear: logins, tokens, personal data.",
      learn: "Under DPDP, transmitting personal data without encryption fails the 'reasonable security safeguards' bar. HTTPS is table stakes.",
      learnUrl: "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
    }));
  }
  return findings;
}
