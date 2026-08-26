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
}

let state: BridgeState = { status: "loading", accessToken: null, user: null };
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
    setState(
      result
        ? { status: "authenticated", accessToken: result.accessToken, user: result.user }
        : { status: "unauthenticated", accessToken: null, user: null },
    );
  } catch {
    setState({ status: "unauthenticated", accessToken: null, user: null });
  }
}

export async function login(email: string, password: string) {
  const result = await authClient.login(email, password);
  setState({ status: "authenticated", accessToken: result.accessToken, user: result.user });
}

/** Completes a SAML SSO login - see pages/SsoCallbackPage.tsx. */
export async function completeSsoLogin(code: string) {
  const result = await authClient.ssoExchange(code);
  setState({ status: "authenticated", accessToken: result.accessToken, user: result.user });
}

export async function logout() {
  await authClient.logout().catch(() => {});
  setState({ status: "unauthenticated", accessToken: null, user: null });
}

/** Used by apiClient after a 401 mid-request, so subsequent requests and any subscribed component pick up the new token. */
export async function silentRefresh(): Promise<string | null> {
  const result = await authClient.refresh();
  if (!result) {
    setState({ status: "unauthenticated", accessToken: null, user: null });
    return null;
  }
  setState({ status: "authenticated", accessToken: result.accessToken, user: result.user });
  return result.accessToken;
}
