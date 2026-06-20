import { describe, it, expect } from 'vitest';
import {
  extractBreezeClaims,
  getPixlflipSsoConfig,
  pixlflipSsoRoutes
} from './pixlflipSso';

describe('pixlflipSso: extractBreezeClaims', () => {
  it('maps the breeze_* claims', () => {
    expect(
      extractBreezeClaims({
        sub: 'u1',
        iss: 'x',
        aud: 'y',
        exp: 0,
        iat: 0,
        breeze_scope: 'organization',
        breeze_org_id: 'org-uuid',
        breeze_partner_id: 'ptr-uuid',
        breeze_role: 'Org Admin'
      })
    ).toEqual({
      scope: 'organization',
      orgId: 'org-uuid',
      partnerId: 'ptr-uuid',
      role: 'Org Admin'
    });
  });

  it('ignores empty strings and non-string values', () => {
    expect(
      extractBreezeClaims({
        sub: 'u1',
        iss: 'x',
        aud: 'y',
        exp: 0,
        iat: 0,
        breeze_scope: '',
        breeze_org_id: 123 as unknown as string
      })
    ).toEqual({ scope: undefined, orgId: undefined, partnerId: undefined, role: undefined });
  });
});

describe('pixlflipSso: getPixlflipSsoConfig', () => {
  it('returns null when the feature is disabled (default test env)', () => {
    // PIXLFLIP_SSO_ENABLED is not set in the test environment.
    expect(getPixlflipSsoConfig()).toBeNull();
  });
});

describe('pixlflipSso routes', () => {
  it('GET /login returns 404 when SSO is disabled', async () => {
    const res = await pixlflipSsoRoutes.request('/login');
    expect(res.status).toBe(404);
  });

  it('GET /callback redirects to /login when SSO is disabled', async () => {
    const res = await pixlflipSsoRoutes.request('/callback?code=x&state=y');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toContain('/login?error=sso_disabled');
  });
});
