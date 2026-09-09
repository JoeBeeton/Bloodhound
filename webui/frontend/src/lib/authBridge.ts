import * as authClient from "./authClient";
import type { UserSummary } from "./types";

/**
 * Single source of truth for auth state, held in memory only (never
 * localStorage - the httpOnly bh_refresh cookie is what survives a reload).
 * Plain module state + subscribe pattern rather than React context, so the
 * apiClient fetch wrapper can trigger a silent refresh outside of any
 * component tree.
 */

type Status = "loading" | "authenticated" | "unauthenticated";

interface BridgeState {
  status: Status;
  accessToken: string | null;
  user: UserSummary | null;
  /**
   * A UX bug found live: SecurityStatusBanner used to own this as local component state, but
   * every page wraps its own fresh <Shell> instance (not a persistent layout under one shared
   * <Outlet/>) - see App.tsx's route table - so the banner remounted, and the dismissal reset,
   * on every single in-app navigation, not just at login. Living here instead survives
   * navigation (this module's state isn't tied to any component's mount lifecycle) and resets
   * only where it actually should: explicitly on the next real login below, not on
   * bootstrap()/silentRefresh() continuing an already-dismissed session across a reload.
   */
  securityBannerDismissed: boolean;
}

let state: BridgeState = { status: "loading", accessToken: null, user: null, securityBannerDismissed: false };
const listeners = new Set<() => void>();

function setState(next: BridgeState) {
  state = next;
  listeners.forEach((listener) => listener());
}

export function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getState() {
  return state;
}

let bootstrapped = false;

/** Safe to call from multiple components on mount - only runs once. */
export async function bootstrap() {
  if (bootstrapped) return;
  bootstrapped = true;
  try {
    const result = await authClient.refresh();
    // Continuing (or failing to continue) an existing session across a page reload, not a new
    // login - carries the current dismissal forward rather than resetting it.
    setState(
      result
        ? { status: "authenticated", accessToken: result.accessToken, user: result.user, securityBannerDismissed: state.securityBannerDismissed }
        : { status: "unauthenticated", accessToken: null, user: null, securityBannerDismissed: state.securityBannerDismissed },
    );
  } catch {
    setState({ status: "unauthenticated", accessToken: null, user: null, securityBannerDismissed: state.securityBannerDismissed });
  }
}

export async function login(email: string, password: string) {
  const result = await authClient.login(email, password);
  setState({ status: "authenticated", accessToken: result.accessToken, user: result.user, securityBannerDismissed: false });
}

/** Completes a SAML SSO login - see pages/SsoCallbackPage.tsx. */
export async function completeSsoLogin(code: string) {
  const result = await authClient.ssoExchange(code);
  setState({ status: "authenticated", accessToken: result.accessToken, user: result.user, securityBannerDismissed: false });
}

export async function logout() {
  await authClient.logout().catch(() => {});
  setState({ status: "unauthenticated", accessToken: null, user: null, securityBannerDismissed: false });
}

export function dismissSecurityBanner() {
  setState({ ...state, securityBannerDismissed: true });
}

/** Used by apiClient after a 401 mid-request, so subsequent requests and any subscribed component pick up the new token. */
export async function silentRefresh(): Promise<string | null> {
  const result = await authClient.refresh();
  if (!result) {
    setState({ status: "unauthenticated", accessToken: null, user: null, securityBannerDismissed: state.securityBannerDismissed });
    return null;
  }
  setState({ status: "authenticated", accessToken: result.accessToken, user: result.user, securityBannerDismissed: state.securityBannerDismissed });
  return result.accessToken;
}
