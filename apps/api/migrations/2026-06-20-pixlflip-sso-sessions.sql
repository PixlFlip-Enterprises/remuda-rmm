-- PixlFlip global SSO consumer: transient OIDC login sessions.
--
-- Mirrors `sso_sessions` but WITHOUT a `provider_id` FK, because the PixlFlip
-- identity provider is configured globally via environment variables (not a
-- per-org `sso_providers` row, which is `org_id NOT NULL`). Rows are single-use
-- (consumed via DELETE ... RETURNING in the callback) and TTL-bounded.
--
-- No RLS: this table holds only transient, non-tenant OIDC flow state (state,
-- nonce, PKCE verifier, post-login redirect path) keyed by an opaque `state`
-- value — exactly like `sso_sessions`, which is likewise un-RLS'd. It has no
-- org/partner/user columns, so the RLS-coverage contract test does not flag it.

CREATE TABLE IF NOT EXISTS pixlflip_sso_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  state varchar(64) NOT NULL,
  nonce varchar(64) NOT NULL,
  code_verifier varchar(128),
  redirect_url varchar(500),
  expires_at timestamp NOT NULL,
  created_at timestamp NOT NULL DEFAULT now(),
  -- Constraint name matches Drizzle's `<table>_<column>_unique` convention so
  -- `pnpm db:check-drift` sees no difference from the schema's `.unique()`.
  CONSTRAINT pixlflip_sso_sessions_state_unique UNIQUE (state)
);

CREATE INDEX IF NOT EXISTS pixlflip_sso_sessions_expires_at_idx
  ON pixlflip_sso_sessions (expires_at);
