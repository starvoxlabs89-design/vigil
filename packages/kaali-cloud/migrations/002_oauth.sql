-- Kaali Cloud — OAuth identities (Google, Meta/Facebook)
-- Run: psql $DATABASE_URL -f migrations/002_oauth.sql

CREATE TABLE IF NOT EXISTS oauth_identities (
  id                BIGSERIAL PRIMARY KEY,
  user_id           BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider          TEXT NOT NULL CHECK (provider IN ('google', 'meta')),
  provider_user_id  TEXT NOT NULL,
  email             TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, provider_user_id)
);
CREATE INDEX IF NOT EXISTS oauth_identities_user_idx ON oauth_identities(user_id);

-- Allow OAuth-only signups: password_hash may be empty for accounts that
-- have only ever authed via a provider. Existing rows are unaffected.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
