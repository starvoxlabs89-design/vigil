-- Kaali Cloud v0.1 — initial schema
-- Run: psql $DATABASE_URL -f migrations/001_init.sql

CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,           -- scrypt: salt$N$r$p$derived
  verified_at   TIMESTAMPTZ,
  plan          TEXT NOT NULL DEFAULT 'free',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,      -- sha256 of the cookie value
  expires_at  TIMESTAMPTZ NOT NULL,
  ip          INET,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);

-- Short-lived tokens: verify-email, forgot-password
CREATE TABLE IF NOT EXISTS auth_tokens (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL CHECK (kind IN ('verify', 'reset')),
  token_hash  TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS auth_tokens_user_idx ON auth_tokens(user_id);

-- Scoped keys for the CLI (`kaali scan --cloud-key ...`) and guard (`onEvent`)
CREATE TABLE IF NOT EXISTS api_keys (
  id           BIGSERIAL PRIMARY KEY,
  user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  prefix       TEXT NOT NULL,            -- first 8 chars, shown in the UI ("k_live_abcd...")
  key_hash     TEXT NOT NULL UNIQUE,     -- sha256 of the full key
  last_used_at TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys(user_id);

-- Ingested events from the CLI (scan findings) and guard (blocked/threats)
CREATE TABLE IF NOT EXISTS events (
  id         BIGSERIAL PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source     TEXT NOT NULL,               -- 'cli' | 'guard'
  target     TEXT,                        -- URL, path, endpoint id
  score      INT,                         -- CLI's Kaali Score
  payload    JSONB NOT NULL,              -- findings[] or guard event object
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS events_user_created_idx ON events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS events_source_idx ON events(source);

-- DPDP consent audit trail (Sec 6, Digital Personal Data Protection Act, 2023)
CREATE TABLE IF NOT EXISTS consent_log (
  id           BIGSERIAL PRIMARY KEY,
  user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind         TEXT NOT NULL,             -- 'signup' | 'withdrawal' | 'reconsent'
  policy_ver   TEXT NOT NULL,
  ip           INET,
  user_agent   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Simple in-memory rate limiter is used at runtime; this table is only a
-- persisted log for abuse forensics.
CREATE TABLE IF NOT EXISTS auth_events (
  id         BIGSERIAL PRIMARY KEY,
  email      TEXT,
  ip         INET,
  kind       TEXT NOT NULL,               -- 'signup' | 'login' | 'login_fail' | 'reset_req' | 'reset'
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS auth_events_ip_idx ON auth_events(ip, created_at DESC);
