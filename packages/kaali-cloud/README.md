# @kaali/cloud

The Kaali dashboard + auth API for **kaali.io**. Auth (signup/verify/login/reset), API-key management for the CLI and guard, event ingestion, DPDP-compliant privacy flow, all in ~600 lines of Node with **one** runtime dependency (`pg`).

## What it does

- **Auth** — email + password with scrypt hashing (Node built-in), verify-email + password reset via magic link, 30-day sessions in HttpOnly cookies, IP-bucket rate-limiting on signup/login/forgot.
- **API keys** — issue scoped `k_live_…` keys to authenticate CLI scans (`kaali scan --cloud-key`) and guard events (`guard({ onEvent: postToKaali })`).
- **Ingest** — `/ingest` accepts CLI scan reports and guard runtime events, stored in JSONB for query later.
- **Dashboard** — stats (scans / guard events / blocks / avg Kaali Score, 30-day windows), recent events, API-key CRUD, "Delete my account" per DPDP §12.
- **DPDP** — consent checkbox at signup logged with IP/UA/policy version, published Privacy Policy, right-to-erasure endpoint.

## Layout

```
packages/kaali-cloud/
├─ src/
│  ├─ index.js       — HTTP server + tiny router
│  ├─ auth.js        — signup / verify / login / logout / forgot / reset / me / erase
│  ├─ keys.js        — API-key CRUD + userByApiKey()
│  ├─ ingest.js      — POST /ingest (CLI + guard events)
│  ├─ dashboard.js   — /me/stats, /me/events
│  ├─ password.js    — scrypt hash/verify
│  ├─ tokens.js      — random tokens + hashing + safe compare + newApiKey()
│  ├─ email.js       — Resend adapter (dev logs to stdout)
│  ├─ ratelimit.js   — in-memory sliding window
│  ├─ util.js        — cookies, JSON, IP
│  ├─ db.js          — lazy pg pool
│  └─ migrate.js     — apply migrations/*.sql
├─ migrations/001_init.sql    — users, sessions, auth_tokens, api_keys, events, consent_log, auth_events
├─ public/          — index.html (auth) · dashboard.html · reset.html · privacy.html
└─ deploy/          — systemd unit + nginx config
```

## Quick start (local)

```bash
# 1. Install (only pg)
cd packages/kaali-cloud && npm install

# 2. Provision a database
createdb kaali
psql kaali -f migrations/001_init.sql

# 3. Configure
cp .env.example .env         # then edit: DATABASE_URL, SESSION_SECRET, RESEND_API_KEY

# 4. Run
node src/index.js            # listening on :4842
```

Without `RESEND_API_KEY` the verify/reset emails print to stdout — copy the link and paste it into your browser. Zero external dep for local dev.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/signup` | `{ email, password, consent:true }` — sends verify email |
| GET  | `/auth/verify?tok=` | mark verified, redirect to dashboard |
| POST | `/auth/login` | `{ email, password }` — sets `kaali_sess` cookie |
| POST | `/auth/logout` | destroy session |
| POST | `/auth/forgot` | `{ email }` — opaque success (never leaks user existence) |
| POST | `/auth/reset` | `{ tok, password }` — kills all sessions after reset |
| GET  | `/me` | whoami |
| DELETE | `/me` | DPDP §12 erasure |
| GET  | `/me/stats` | 30-day rollup |
| GET  | `/me/events?limit=` | recent scan + guard events |
| GET  | `/me/keys` | list keys (never returns full key) |
| POST | `/me/keys` | create — returns full key **once** |
| POST | `/me/keys/:id/revoke` | revoke a key |
| POST | `/ingest` | Bearer or `?key=` — accepts CLI + guard events |

## Deploy (Hostinger Mumbai VPS)

```bash
# On the VPS
sudo mkdir -p /opt/kaali && sudo chown $USER:$USER /opt/kaali
cd /opt/kaali && git clone https://github.com/starvoxlabs89-design/kaali.git
cd kaali/packages/kaali-cloud
npm install --production
cp .env.example .env && $EDITOR .env

# Postgres
sudo -u postgres createdb kaali
sudo -u postgres psql -c "CREATE USER kaali WITH PASSWORD 'CHANGE_ME';"
sudo -u postgres psql kaali -f migrations/001_init.sql

# systemd + nginx
sudo cp deploy/kaali-cloud.service /etc/systemd/system/
sudo cp deploy/nginx.conf /etc/nginx/sites-available/kaali.conf
sudo ln -s /etc/nginx/sites-available/kaali.conf /etc/nginx/sites-enabled/
sudo systemctl daemon-reload
sudo systemctl enable --now kaali-cloud
sudo nginx -t && sudo systemctl reload nginx

# TLS
sudo certbot --nginx -d api.kaali.io -d app.kaali.io
```

## Design decisions (honest)

- **Node built-in `scrypt`** over bcrypt — avoids a native dep. Params tuned for ~50ms hash time.
- **Session cookies** stored server-side; the cookie holds a random 32-byte token, DB holds its SHA-256. Password reset kills all sessions.
- **No CSRF library** — CORS with `credentials:'include'` + `SameSite=Lax` covers the browser flow; the `/ingest` endpoint is API-key authenticated so it isn't a CSRF target.
- **Opaque signup/forgot** — never confirm-or-deny whether an email exists.
- **Zero external deps for email in dev** — links print to stdout so you can develop without email loops.
- **DPDP built in, not bolted on** — consent logged at signup with policy version, IP, UA; erasure endpoint cascades cleanly.

## Security TODO before public launch

- [ ] Rotate `SESSION_SECRET` and `CSRF_SECRET` to production values
- [ ] Enable `COOKIE_SECURE=1` in prod
- [ ] Add TOTP 2FA (roadmap)
- [ ] Point `RESEND_API_KEY` at a domain-verified sender
- [ ] Set up daily Postgres backups + rotate
- [ ] Appoint DPO before the DPDP May 2027 hard-enforcement date

## License

MIT © 2026 Starvox Labs
