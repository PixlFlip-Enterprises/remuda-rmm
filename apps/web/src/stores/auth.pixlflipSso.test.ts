import { beforeEach, describe, expect, it, vi } from 'vitest';
import { bootstrapFromPixlflipSsoCode, useAuthStore } from './auth';

const makeResponse = (payload: unknown, ok = true, status = ok ? 200 : 500): Response =>
  ({
    ok,
    status,
    json: vi.fn().mockResolvedValue(payload),
  }) as unknown as Response;

const resetStore = () =>
  useAuthStore.setState({
    user: null,
    tokens: null,
    isAuthenticated: false,
    isLoading: false,
    mfaPending: false,
    mfaTempToken: null,
  });

describe('bootstrapFromPixlflipSsoCode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.removeItem('breeze-auth');
    document.cookie = 'breeze_csrf_token=csrf-test-token; path=/';
    resetStore();
  });

  it('exchanges the code, fetches the user, and populates the store', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(makeResponse({ accessToken: 'acc-new', expiresInSeconds: 900 })) // /sso/exchange
      .mockResolvedValueOnce(
        makeResponse({ id: 'user-1', email: 'u@example.com', name: 'U', mfaEnabled: false }),
      ) // /users/me
      .mockResolvedValue(makeResponse({})); // fetchAndApplyPreferences + any trailing calls
    vi.stubGlobal('fetch', fetchMock);

    const ok = await bootstrapFromPixlflipSsoCode('code-123');

    expect(ok).toBe(true);
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.tokens?.accessToken).toBe('acc-new');

    const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/sso/exchange');
    expect(JSON.parse(opts.body as string)).toEqual({ code: 'code-123' });
  });

  it('returns false (no session) when the code exchange fails', async () => {
    const fetchMock = vi.fn().mockResolvedValue(makeResponse({ error: 'bad' }, false, 400));
    vi.stubGlobal('fetch', fetchMock);

    const ok = await bootstrapFromPixlflipSsoCode('bad-code');

    expect(ok).toBe(false);
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('returns false when the user lookup fails after a good exchange', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(makeResponse({ accessToken: 'acc-new', expiresInSeconds: 900 }))
      .mockResolvedValueOnce(makeResponse(null, false, 401));
    vi.stubGlobal('fetch', fetchMock);

    const ok = await bootstrapFromPixlflipSsoCode('code-123');

    expect(ok).toBe(false);
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });
});
