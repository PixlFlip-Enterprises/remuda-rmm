import { Hono } from 'hono';
import {
  cfAccessTrustEnabled,
  PIXLFLIP_SSO_ENABLED,
  PIXLFLIP_SSO_ISSUER,
  PIXLFLIP_SSO_CLIENT_ID,
  PIXLFLIP_SSO_CLIENT_SECRET,
} from '../config/env';
import { envFlag } from '../utils/envFlag';

export const configRoutes = new Hono();

// GET /api/v1/config — returns feature flags for the UI. No auth required;
// flags are derived purely from server env, not user state, so self-hosted
// deployments can fetch this before login to decide what to render.
configRoutes.get('/', (c) => {
  const hasExternalServices = !!process.env.BREEZE_BILLING_URL;
  return c.json({
    features: {
      billing: hasExternalServices,
      support: hasExternalServices,
    },
    cfAccessLogin: {
      enabled: cfAccessTrustEnabled(),
    },
    // Whether "Sign in with PixlFlip" should be offered. Mirrors the fail-closed
    // gating in routes/auth/pixlflipSso.ts: enabled only when the feature flag
    // is on AND the provider is fully configured.
    pixlflipSso: {
      enabled:
        PIXLFLIP_SSO_ENABLED &&
        !!PIXLFLIP_SSO_ISSUER &&
        !!PIXLFLIP_SSO_CLIENT_ID &&
        !!PIXLFLIP_SSO_CLIENT_SECRET,
    },
    // Runtime source of truth for whether self-service MSP registration is
    // open. The web bundle can't read PUBLIC_ENABLE_REGISTRATION at runtime
    // (it's frozen into the prebuilt image at build time), so the UI gates the
    // "Register your MSP" link and the register pages on this value instead —
    // keeping it in lockstep with the same ENABLE_REGISTRATION env the
    // /auth/register-partner enforcement reads (issue #1308).
    registration: {
      enabled: envFlag('ENABLE_REGISTRATION', false),
    },
  });
});
