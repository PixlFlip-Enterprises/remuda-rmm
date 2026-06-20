import { Hono } from 'hono';
import { eq, and, gt, ilike } from 'drizzle-orm';
import { createHmac, timingSafeEqual } from 'crypto';
import { db, withSystemDbAccessContext } from '../../db';
import {
  pixlflipSsoSessions,
  users,
  organizations,
  organizationUsers,
  roles
} from '../../db/schema';
import {
  generateState,
  generateNonce,
  generatePKCEChallenge,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  getUserInfo,
  verifyIdTokenSignature,
  assertEmailVerified,
  mapUserAttributes,
  discoverOIDCConfig,
  type OIDCConfig,
  type IDTokenClaims
} from '../../services/sso';
import {
  createTokenPair,
  createSession,
  mintRefreshTokenFamily,
  bindRefreshJtiToFamily
} from '../../services';
import { getTrustedClientIp } from '../../services/clientIp';
import { createSsoTokenExchangeGrant } from '../sso';
import { getCookieValue } from './helpers';
import {
  PIXLFLIP_SSO_ENABLED,
  PIXLFLIP_SSO_ISSUER,
  PIXLFLIP_SSO_CLIENT_ID,
  PIXLFLIP_SSO_CLIENT_SECRET,
  PIXLFLIP_SSO_DEFAULT_ORG_ROLE
} from '../../config/env';

export const pixlflipSsoRoutes = new Hono();

// ============================================
// PixlFlip federated login (OIDC consumer)
// ============================================
//
// PixlFlip.net acts as the upstream OpenID Connect identity provider. Unlike the
// per-org SSO in routes/sso.ts (provider rows in `sso_providers`, org_id NOT
// NULL), the PixlFlip provider is GLOBAL and configured via environment vars,
// so there is no DB provider row and the transient flow state lives in the
// `pixlflip_sso_sessions` table (no provider FK).
//
// Org-scope first (PR #4): the callback provisions the user into the Breeze org
// named by the `breeze_org_id` claim that PixlFlip emits (PR #3) and mints an
// organization-scope session. Partner/system scopes are handled in PR #5;
// durable identity linking (`user_sso_identities`) in PR #6.

const STATE_COOKIE_NAME = 'pixlflip_sso_state';
const STATE_COOKIE_PATH = '/api/v1/sso/pixlflip/callback';
const STATE_COOKIE_MAX_AGE_SECONDS = 10 * 60;
const SESSION_TTL_MS = 10 * 60 * 1000;

interface PixlflipSsoConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  defaultOrgRole: string;
}

/**
 * Resolve the PixlFlip provider config, or null when the feature is disabled or
 * incompletely configured. Returning null lets the routes fail closed rather
 * than start a flow they could not complete.
 */
export function getPixlflipSsoConfig(): PixlflipSsoConfig | null {
  if (!PIXLFLIP_SSO_ENABLED) return null;
  if (!PIXLFLIP_SSO_ISSUER || !PIXLFLIP_SSO_CLIENT_ID || !PIXLFLIP_SSO_CLIENT_SECRET) {
    return null;
  }
  return {
    issuer: PIXLFLIP_SSO_ISSUER,
    clientId: PIXLFLIP_SSO_CLIENT_ID,
    clientSecret: PIXLFLIP_SSO_CLIENT_SECRET,
    defaultOrgRole: PIXLFLIP_SSO_DEFAULT_ORG_ROLE || 'Org Technician'
  };
}

/** The Breeze-tenant claims PixlFlip emits in the id_token (PR #3). */
export interface BreezeClaims {
  scope?: string;
  orgId?: string;
  partnerId?: string;
  role?: string;
}

export function extractBreezeClaims(claims: IDTokenClaims | Record<string, unknown>): BreezeClaims {
  const asStr = (v: unknown): string | undefined =>
    typeof v === 'string' && v.length > 0 ? v : undefined;
  return {
    scope: asStr(claims['breeze_scope']),
    orgId: asStr(claims['breeze_org_id']),
    partnerId: asStr(claims['breeze_partner_id']),
    role: asStr(claims['breeze_role'])
  };
}

// ---- Browser-binding cookie (login-CSRF protection), same design as routes/sso.ts ----

function isSecureCookieEnvironment(): boolean {
  return process.env.NODE_ENV === 'production';
}

function cookieSecuritySuffix(): string {
  return `; SameSite=Lax${isSecureCookieEnvironment() ? '; Secure' : ''}`;
}

function stateCookieValue(state: string): string | null {
  const secret =
    process.env.APP_ENCRYPTION_KEY?.trim() || process.env.SECRET_ENCRYPTION_KEY?.trim();
  if (!secret) return null;
  return createHmac('sha256', secret).update(`pixlflip-sso-login-state:${state}`).digest('hex');
}

function buildStateCookie(state: string): string | null {
  const value = stateCookieValue(state);
  if (!value) return null;
  return `${STATE_COOKIE_NAME}=${encodeURIComponent(value)}; Path=${STATE_COOKIE_PATH}; HttpOnly${cookieSecuritySuffix()}; Max-Age=${STATE_COOKIE_MAX_AGE_SECONDS}`;
}

function clearStateCookieHeader(): string {
  return `${STATE_COOKIE_NAME}=; Path=${STATE_COOKIE_PATH}; HttpOnly${cookieSecuritySuffix()}; Max-Age=0`;
}

function isValidStateCookie(state: string, cookieHeader: string | undefined): boolean {
  const cookieValue = getCookieValue(cookieHeader, STATE_COOKIE_NAME);
  const expected = stateCookieValue(state);
  if (!cookieValue || !expected) return false;
  const left = Buffer.from(cookieValue, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

// ---- URL helpers ----

function canonicalPublicBaseUrl(): string {
  const configured = (
    process.env.PUBLIC_URL ||
    process.env.PUBLIC_APP_URL ||
    process.env.DASHBOARD_URL ||
    'http://localhost:3000'
  ).trim();
  try {
    return new URL(configured).origin;
  } catch {
    return 'http://localhost:3000';
  }
}

function buildCallbackUri(): string {
  return `${canonicalPublicBaseUrl()}/api/v1/sso/pixlflip/callback`;
}

/** Only allow internal, non-protocol-relative redirect paths (open-redirect guard). */
function normalizeRedirectPath(input: string | undefined | null): string {
  if (!input || !input.startsWith('/') || input.startsWith('//')) return '/';
  return input;
}

/**
 * Resolve an organization-scope role id within `orgId`, preferring the Breeze
 * role name from the claim, then the configured default. Case-insensitive.
 */
async function resolveOrgRoleId(
  orgId: string,
  breezeRole: string | undefined,
  defaultRole: string
): Promise<string | null> {
  const candidates = [breezeRole, defaultRole].filter((n): n is string => !!n && n.length > 0);
  for (const name of candidates) {
    const [role] = await db
      .select({ id: roles.id })
      .from(roles)
      .where(and(eq(roles.orgId, orgId), eq(roles.scope, 'organization'), ilike(roles.name, name)))
      .limit(1);
    if (role) return role.id;
  }
  return null;
}

// ============================================
// Routes
// ============================================

// Start: redirect the browser to PixlFlip's authorization endpoint.
pixlflipSsoRoutes.get('/login', async (c) => {
  const cfg = getPixlflipSsoConfig();
  if (!cfg) {
    return c.json({ error: 'PixlFlip SSO is not enabled' }, 404);
  }

  const redirectUrl = normalizeRedirectPath(c.req.query('redirect'));

  let discovery;
  try {
    discovery = await discoverOIDCConfig(cfg.issuer);
  } catch (error) {
    console.error('[pixlflip-sso/login] OIDC discovery failed:', error);
    return c.json({ error: 'Failed to discover PixlFlip OIDC configuration' }, 502);
  }

  const config: OIDCConfig = {
    issuer: cfg.issuer,
    clientId: cfg.clientId,
    clientSecret: cfg.clientSecret,
    authorizationUrl: discovery.authorization_endpoint,
    tokenUrl: discovery.token_endpoint,
    userInfoUrl: discovery.userinfo_endpoint,
    jwksUrl: discovery.jwks_uri,
    scopes: 'openid profile email'
  };

  const pkce = generatePKCEChallenge();
  const state = generateState();
  const nonce = generateNonce();

  await withSystemDbAccessContext(async () =>
    db.insert(pixlflipSsoSessions).values({
      state,
      nonce,
      codeVerifier: pkce.codeVerifier,
      redirectUrl,
      expiresAt: new Date(Date.now() + SESSION_TTL_MS)
    })
  );

  const authUrl = buildAuthorizationUrl({
    config,
    state,
    nonce,
    redirectUri: buildCallbackUri(),
    pkce
  });

  const stateCookie = buildStateCookie(state);
  if (!stateCookie) {
    // Fail closed: without the signing secret we cannot bind the browser.
    return c.json({ error: 'SSO login binding secret is not configured on this instance' }, 500);
  }
  c.header('Set-Cookie', stateCookie, { append: true });
  return c.redirect(authUrl);
});

// Callback: verify, provision into the breeze_org_id org, mint a session.
pixlflipSsoRoutes.get('/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');
  const errorDescription = c.req.query('error_description');

  const clearCookie = () => c.header('Set-Cookie', clearStateCookieHeader(), { append: true });

  const cfg = getPixlflipSsoConfig();
  if (!cfg) {
    return c.redirect('/login?error=sso_disabled');
  }

  if (error) {
    clearCookie();
    return c.redirect(`/login?error=sso_error&message=${encodeURIComponent(errorDescription || error)}`);
  }
  if (!code || !state) {
    clearCookie();
    return c.redirect('/login?error=invalid_callback');
  }

  // Browser-binding check BEFORE consuming the session (login-CSRF guard).
  if (!isValidStateCookie(state, c.req.header('cookie'))) {
    console.warn('[pixlflip-sso/callback] Missing or invalid login-binding cookie');
    clearCookie();
    return c.redirect('/login?error=invalid_callback');
  }

  // Atomically claim the session (single-use; replay loses the race).
  const [session] = await withSystemDbAccessContext(async () =>
    db
      .delete(pixlflipSsoSessions)
      .where(and(eq(pixlflipSsoSessions.state, state), gt(pixlflipSsoSessions.expiresAt, new Date())))
      .returning()
  );

  if (!session) {
    clearCookie();
    return c.redirect('/login?error=session_expired');
  }

  try {
    let discovery;
    try {
      discovery = await discoverOIDCConfig(cfg.issuer);
    } catch (e) {
      console.error('[pixlflip-sso/callback] OIDC discovery failed:', e);
      clearCookie();
      return c.redirect('/login?error=sso_error&message=discovery_failed');
    }

    const config: OIDCConfig = {
      issuer: cfg.issuer,
      clientId: cfg.clientId,
      clientSecret: cfg.clientSecret,
      authorizationUrl: discovery.authorization_endpoint,
      tokenUrl: discovery.token_endpoint,
      userInfoUrl: discovery.userinfo_endpoint,
      jwksUrl: discovery.jwks_uri,
      scopes: 'openid profile email'
    };

    const tokens = await exchangeCodeForTokens({
      config,
      code,
      redirectUri: buildCallbackUri(),
      codeVerifier: session.codeVerifier || undefined
    });

    // The id_token carries the breeze_* claims. PixlFlip always publishes a
    // JWKS, so verify the signature cryptographically and enforce
    // email_verified before trusting any email.
    if (!tokens.id_token) {
      clearCookie();
      return c.redirect('/login?error=sso_error&message=missing_id_token');
    }
    const claims = await verifyIdTokenSignature(tokens.id_token, config, session.nonce);
    if (claims.email) {
      assertEmailVerified(claims);
    }

    const breeze = extractBreezeClaims(claims);

    // PR #4 handles org scope only. Other scopes (and "no mapping") are punted
    // to PR #5; surface a clear reason rather than silently mis-provisioning.
    if (!breeze.scope) {
      clearCookie();
      return c.redirect('/login?error=sso_no_breeze_identity');
    }
    if (breeze.scope !== 'organization') {
      clearCookie();
      return c.redirect('/login?error=sso_scope_unsupported');
    }
    if (!breeze.orgId) {
      clearCookie();
      return c.redirect('/login?error=sso_missing_org');
    }

    // Identity (email/name) from the server-to-server userinfo call.
    const userInfo = await getUserInfo(config, tokens.access_token);
    const attrs = mapUserAttributes(userInfo, { email: 'email', name: 'name' });
    if (!attrs.email) {
      clearCookie();
      return c.redirect('/login?error=sso_error&message=missing_email');
    }

    const provisioned = await withSystemDbAccessContext(async () => {
      // The org named by the claim must exist in Breeze (PixlFlip only points
      // at pre-existing tenant UUIDs).
      const [org] = await db
        .select({ id: organizations.id, partnerId: organizations.partnerId })
        .from(organizations)
        .where(eq(organizations.id, breeze.orgId!))
        .limit(1);
      if (!org) return { error: 'sso_unknown_org' as const };

      const roleId = await resolveOrgRoleId(org.id, breeze.role, cfg.defaultOrgRole);
      if (!roleId) return { error: 'sso_role_unresolved' as const };

      let [user] = await db
        .select()
        .from(users)
        .where(eq(users.email, attrs.email.toLowerCase()))
        .limit(1);

      if (!user) {
        const [created] = await db
          .insert(users)
          .values({
            partnerId: org.partnerId,
            orgId: org.id,
            email: attrs.email.toLowerCase(),
            name: attrs.name,
            status: 'active',
            passwordHash: null // federated users have no local password
          })
          .returning();
        if (!created) return { error: 'sso_user_creation_failed' as const };
        user = created;
      }

      // Ensure org membership at the resolved role.
      const [membership] = await db
        .select({ roleId: organizationUsers.roleId })
        .from(organizationUsers)
        .where(and(eq(organizationUsers.userId, user.id), eq(organizationUsers.orgId, org.id)))
        .limit(1);
      if (!membership) {
        await db.insert(organizationUsers).values({ orgId: org.id, userId: user.id, roleId });
      }

      // Read back the effective org role for the token.
      const [orgUser] = await db
        .select({
          roleId: organizationUsers.roleId,
          roleScope: roles.scope
        })
        .from(organizationUsers)
        .innerJoin(roles, eq(roles.id, organizationUsers.roleId))
        .where(and(eq(organizationUsers.userId, user.id), eq(organizationUsers.orgId, org.id)))
        .limit(1);
      if (!orgUser || orgUser.roleScope !== 'organization') {
        return { error: 'sso_invalid_role_scope' as const };
      }

      await db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, user.id));

      return { user, orgId: org.id, roleId: orgUser.roleId };
    });

    if ('error' in provisioned) {
      clearCookie();
      return c.redirect(`/login?error=${provisioned.error}`);
    }

    // Mint an organization-scope session (same shape + refresh-family
    // reuse-detection as the per-org SSO and password logins).
    const tokenPayload = {
      sub: provisioned.user.id,
      email: provisioned.user.email,
      roleId: provisioned.roleId,
      orgId: provisioned.orgId,
      partnerId: null,
      scope: 'organization' as const,
      mfa: false
    };

    const familyId = await mintRefreshTokenFamily(provisioned.user.id);
    const { accessToken, refreshToken, refreshJti, expiresInSeconds } = await createTokenPair(
      tokenPayload,
      { refreshFam: familyId }
    );
    await bindRefreshJtiToFamily(refreshJti, familyId);

    await createSession({
      userId: provisioned.user.id,
      ipAddress: getTrustedClientIp(c),
      userAgent: c.req.header('user-agent') || 'unknown'
    });

    const tokenExchangeCode = createSsoTokenExchangeGrant(accessToken, refreshToken, expiresInSeconds);
    const redirectPath = normalizeRedirectPath(session.redirectUrl ?? '/');
    clearCookie();
    return c.redirect(`${redirectPath}#ssoCode=${encodeURIComponent(tokenExchangeCode)}`);
  } catch (err: any) {
    console.error('[pixlflip-sso/callback] error:', err);
    clearCookie();
    return c.redirect(`/login?error=sso_error&message=${encodeURIComponent(err?.message || 'Authentication failed')}`);
  }
});
