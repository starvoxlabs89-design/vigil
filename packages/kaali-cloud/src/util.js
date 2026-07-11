// Zero-dep helpers: JSON body reading, cookies, JSON responses, request IP.

export async function readJson(req, maxBytes = 100_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > maxBytes) { req.destroy(); reject(new Error("payload too large")); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      const buf = Buffer.concat(chunks);
      if (buf.length === 0) return resolve({});
      try { resolve(JSON.parse(buf.toString("utf8"))); } catch { reject(new Error("bad json")); }
    });
    req.on("error", reject);
  });
}

export function json(res, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

export function text(res, status, body, contentType = "text/plain; charset=utf-8") {
  res.statusCode = status;
  res.setHeader("content-type", contentType);
  res.end(body);
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const pair of String(header).split(";")) {
    const idx = pair.indexOf("=");
    if (idx < 0) continue;
    const k = pair.slice(0, idx).trim();
    const v = decodeURIComponent(pair.slice(idx + 1).trim());
    if (k) out[k] = v;
  }
  return out;
}

export function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.expires) parts.push(`Expires=${opts.expires.toUTCString()}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  if ((process.env.COOKIE_SECURE || "0") === "1") parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  const prev = res.getHeader("set-cookie");
  const arr = Array.isArray(prev) ? prev.slice() : prev ? [String(prev)] : [];
  arr.push(parts.join("; "));
  res.setHeader("set-cookie", arr);
}

export function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return String(fwd).split(",")[0].trim();
  return req.socket?.remoteAddress || null;
}
