-- Durable PixlFlip identity links (issuer + subject → Breeze user).
--
-- Federated login matches on the stable OIDC `sub` (not email alone), so a
-- changed or reused email can't take over an account. Mirrors the per-org
-- `user_sso_identities` but WITHOUT a `provider_id` FK (the PixlFlip provider is
-- global/env-configured, not a `sso_providers` row).
--
-- User-id-scoped (RLS shape 6): policies key on breeze_current_user_id(), with
-- the same partner/org-admin visibility OR-branch as user_sso_identities. The
-- federated callback writes via the system DB context (RLS bypassed); these
-- policies gate any authenticated read (e.g. a user viewing linked identities).

CREATE TABLE IF NOT EXISTS pixlflip_sso_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issuer varchar(255) NOT NULL,
  subject varchar(255) NOT NULL,
  email varchar(255),
  last_login_at timestamp,
  created_at timestamp NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS pixlflip_sso_identities_issuer_subject_unique
  ON pixlflip_sso_identities (issuer, subject);
CREATE INDEX IF NOT EXISTS pixlflip_sso_identities_user_id_idx
  ON pixlflip_sso_identities (user_id);

-- RLS (shape 6: user-id-scoped), mirroring user_sso_identities.
DROP POLICY IF EXISTS breeze_user_isolation_select ON pixlflip_sso_identities;
DROP POLICY IF EXISTS breeze_user_isolation_insert ON pixlflip_sso_identities;
DROP POLICY IF EXISTS breeze_user_isolation_update ON pixlflip_sso_identities;
DROP POLICY IF EXISTS breeze_user_isolation_delete ON pixlflip_sso_identities;
ALTER TABLE pixlflip_sso_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE pixlflip_sso_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY breeze_user_isolation_select ON pixlflip_sso_identities
  FOR SELECT USING (
    user_id = public.breeze_current_user_id()
    OR EXISTS (SELECT 1 FROM users u WHERE u.id = pixlflip_sso_identities.user_id
               AND (public.breeze_has_partner_access(u.partner_id)
                    OR public.breeze_has_org_access(u.org_id)))
  );
CREATE POLICY breeze_user_isolation_insert ON pixlflip_sso_identities
  FOR INSERT WITH CHECK (
    user_id = public.breeze_current_user_id()
    OR EXISTS (SELECT 1 FROM users u WHERE u.id = pixlflip_sso_identities.user_id
               AND (public.breeze_has_partner_access(u.partner_id)
                    OR public.breeze_has_org_access(u.org_id)))
  );
CREATE POLICY breeze_user_isolation_update ON pixlflip_sso_identities
  FOR UPDATE USING (
    user_id = public.breeze_current_user_id()
    OR EXISTS (SELECT 1 FROM users u WHERE u.id = pixlflip_sso_identities.user_id
               AND (public.breeze_has_partner_access(u.partner_id)
                    OR public.breeze_has_org_access(u.org_id)))
  )
  WITH CHECK (
    user_id = public.breeze_current_user_id()
    OR EXISTS (SELECT 1 FROM users u WHERE u.id = pixlflip_sso_identities.user_id
               AND (public.breeze_has_partner_access(u.partner_id)
                    OR public.breeze_has_org_access(u.org_id)))
  );
CREATE POLICY breeze_user_isolation_delete ON pixlflip_sso_identities
  FOR DELETE USING (
    user_id = public.breeze_current_user_id()
    OR EXISTS (SELECT 1 FROM users u WHERE u.id = pixlflip_sso_identities.user_id
               AND (public.breeze_has_partner_access(u.partner_id)
                    OR public.breeze_has_org_access(u.org_id)))
  );
