import type { AuthState } from "./types";

/** Exported for reuse by any other endpoint that can return the same 429 + Retry-After shape - see ChangePasswordModal, which hits the same LoginAttemptLimiter through a different endpoint. */
export function formatRetryAfter(res: Response): string {
  const seconds = Number(res.headers.get("Retry-After"));
  if (!Number.isFinite(seconds) || seconds <= 0) return "a few minutes";
  const minutes = Math.ceil(seconds / 60);
  return minutes === 1 ? "1 minute" : `${minutes} minutes`;
}

async function parseJsonOrThrow(res: Response): Promise<AuthState> {
  if (!res.ok) {
    // 429 handled explicitly, not folded into the generic "Something went wrong" case below - a
    // product review found a rate-limited login previously showed that same generic message,
    // which is actively counterproductive (it reads as transient and invites immediately retrying
    // the exact thing being throttled) instead of telling the user they're locked out and for
    // roughly how long.
    if (res.status === 429) {
      throw new Error(`Too many failed attempts. Try again in ${formatRetryAfter(res)}.`);
    }
    throw new Error(res.status === 401 ? "Invalid email or password." : "Something went wrong. Try again.");
  }
  return res.json();
}

export async function login(email: string, password: string): Promise<AuthState> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ email, password }),
  });
  return parseJsonOrThrow(res);
}

/** Returns null (not authenticated) rather than throwing on a 401 - that's the expected "no session" case. */
export async function refresh(): Promise<AuthState | null> {
  const res = await fetch("/api/auth/refresh", { method: "POST", credentials: "include" });
  if (res.status === 401) return null;
  return parseJsonOrThrow(res);
}

/** Trades a one-time SAML handoff code (see /sso/callback) for real tokens - same response shape as login. */
export async function ssoExchange(code: string): Promise<AuthState> {
  const res = await fetch("/api/auth/sso/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ code }),
  });
  if (!res.ok) {
    throw new Error("That SSO sign-in link is invalid or has expired. Try signing in again.");
  }
  return parseJsonOrThrow(res);
}

export async function logout(): Promise<void> {
  await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
}
