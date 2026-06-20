import { useEffect, useState } from 'react';
import {
  bootstrapFromCfAccessRedirect,
  bootstrapFromPixlflipSsoCode,
  restoreAccessTokenFromCookie,
  useAuthStore,
} from '../../stores/auth';
import { Loader2 } from 'lucide-react';
import { navigateTo } from '../../lib/navigation';

const CF_ACCESS_LOGIN_PARAM = 'cf-access-login';

function consumeCfAccessLoginParam(): boolean {
  if (typeof window === 'undefined') return false;
  const params = new URLSearchParams(window.location.search);
  if (params.get(CF_ACCESS_LOGIN_PARAM) !== 'success') return false;
  params.delete(CF_ACCESS_LOGIN_PARAM);
  const cleanSearch = params.toString();
  const cleanUrl =
    window.location.pathname +
    (cleanSearch ? `?${cleanSearch}` : '') +
    window.location.hash;
  window.history.replaceState({}, '', cleanUrl);
  return true;
}

// The PixlFlip SSO callback redirects back with a one-time `#ssoCode=<code>` in
// the URL hash. Read it and strip it from the URL (so a refresh / share can't
// replay it) before exchanging it for a session.
function consumePixlflipSsoCode(): string | null {
  if (typeof window === 'undefined') return null;
  const hash = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash;
  const params = new URLSearchParams(hash);
  const code = params.get('ssoCode');
  if (!code) return null;
  params.delete('ssoCode');
  const cleanHash = params.toString();
  const cleanUrl =
    window.location.pathname +
    window.location.search +
    (cleanHash ? `#${cleanHash}` : '');
  window.history.replaceState({}, '', cleanUrl);
  return code;
}

export default function AuthOverlay() {
  const { isAuthenticated, isLoading, tokens } = useAuthStore();
  const [isChecking, setIsChecking] = useState(true);
  const [isRecovering, setIsRecovering] = useState(false);
  const [recoverAttempted, setRecoverAttempted] = useState(false);
  const [cfBootstrapAttempted, setCfBootstrapAttempted] = useState(false);
  const [ssoBootstrapAttempted, setSsoBootstrapAttempted] = useState(false);
  const [fadeState, setFadeState] = useState<'visible' | 'fading' | 'hidden'>('visible');

  useEffect(() => {
    // Give the store time to rehydrate from localStorage
    const timer = setTimeout(() => {
      setIsChecking(false);
    }, 50);

    return () => clearTimeout(timer);
  }, []);

  // Safety net: if the overlay is still visible after 10 seconds, force redirect to login.
  // This prevents the user from being stuck on "Loading..." indefinitely.
  useEffect(() => {
    const safetyTimer = setTimeout(() => {
      const state = useAuthStore.getState();
      if (!state.isAuthenticated || !state.tokens?.accessToken) {
        redirectToLogin();
      }
    }, 10_000);

    return () => clearTimeout(safetyTimer);
  }, []);

  useEffect(() => {
    let cancelled = false;

    if (isChecking || isLoading) return;

    // Fast path: tokens were rehydrated from localStorage — no network needed
    if (isAuthenticated && tokens?.accessToken) {
      return;
    }

    // PixlFlip SSO redirect bootstrap: the callback redirects here with a
    // one-time `#ssoCode`. Exchange it for a session before falling through to
    // the "no session, redirect to /login" path. Runs once per overlay mount.
    if (!isAuthenticated && !ssoBootstrapAttempted) {
      const ssoCode = consumePixlflipSsoCode();
      if (ssoCode) {
        setSsoBootstrapAttempted(true);
        setIsRecovering(true);
        void bootstrapFromPixlflipSsoCode(ssoCode).then((ok) => {
          if (cancelled) return;
          setIsRecovering(false);
          if (!ok) {
            void navigateTo('/login?error=sso', { replace: true });
          }
        });
        return () => { cancelled = true; };
      }
    }

    // CF Access redirect bootstrap: the server's GET /api/v1/auth/cf-access-login
    // endpoint sets a refresh cookie and redirects here with ?cf-access-login=success.
    // The SPA has no in-memory session yet, so trade the cookie for tokens and fetch
    // the user before falling through to the normal "no session, redirect to /login"
    // path. This runs once per overlay mount.
    if (!isAuthenticated && !cfBootstrapAttempted) {
      const shouldBootstrap = consumeCfAccessLoginParam();
      if (shouldBootstrap) {
        setCfBootstrapAttempted(true);
        setIsRecovering(true);
        void bootstrapFromCfAccessRedirect().then((ok) => {
          if (cancelled) return;
          setIsRecovering(false);
          if (!ok) {
            void navigateTo('/login?error=cf-access', { replace: true });
          }
        });
        return () => { cancelled = true; };
      }
    }

    // Slow path: authenticated but no token (e.g. first load after login on another tab)
    if (isAuthenticated && !tokens?.accessToken && !recoverAttempted) {
      setRecoverAttempted(true);
      setIsRecovering(true);

      void restoreAccessTokenFromCookie().then((restored) => {
        if (cancelled) return;
        setIsRecovering(false);

        if (!restored) {
          redirectToLogin();
        }
      });

      return () => { cancelled = true; };
    }

    if (isRecovering) {
      return () => { cancelled = true; };
    }

    if (!isAuthenticated) {
      redirectToLogin();
    }

    return () => { cancelled = true; };
  }, [isAuthenticated, isLoading, isChecking, tokens, recoverAttempted, isRecovering, cfBootstrapAttempted, ssoBootstrapAttempted]);

  // Authenticated with token — fade out then unmount
  const shouldHide = !isChecking && !isLoading && isAuthenticated && !!tokens?.accessToken;

  useEffect(() => {
    if (shouldHide && fadeState === 'visible') {
      // Start fade-out on next frame so the browser paints opacity:1 first
      requestAnimationFrame(() => setFadeState('fading'));
    }
  }, [shouldHide, fadeState]);

  if (fadeState === 'hidden') {
    return null;
  }

  if (shouldHide) {
    return (
      <div
        className={`fixed inset-0 z-50 flex items-center justify-center bg-background transition-opacity duration-300 pointer-events-none ${fadeState === 'fading' ? 'opacity-0' : 'opacity-100'}`}
        onTransitionEnd={() => setFadeState('hidden')}
      />
    );
  }

  // Still initializing or recovering — show overlay
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background">
      <div className="text-center">
        <Loader2 className="mx-auto h-8 w-8 animate-spin text-primary" />
        <p className="mt-4 text-sm text-muted-foreground">
          {isChecking || isLoading || isRecovering ? 'Loading...' : 'Redirecting to login...'}
        </p>
      </div>
    </div>
  );
}

function redirectToLogin() {
  void navigateTo('/login', { replace: true });
}
