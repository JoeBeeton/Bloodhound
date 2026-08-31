import * as bridge from "./authBridge";

/**
 * Fetch wrapper for protected central-server-proxied endpoints: attaches the
 * bearer token and retries once via a silent refresh on a 401. Nothing calls
 * this yet (Milestone 1 has no protected data endpoints in the UI), but it's
 * needed as soon as Milestone 2 adds target endpoints.
 */
export async function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const attempt = async (): Promise<Response> => {
    const token = bridge.getState().accessToken;
    const headers = new Headers(init.headers);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    return fetch(input, { ...init, headers, credentials: "include" });
  };

  let res = await attempt();
  if (res.status === 401) {
    const newToken = await bridge.silentRefresh();
    if (newToken) {
      res = await attempt();
    }
  }
  return res;
}

/**
 * Paginated list endpoints (subdomains, findings) carry the true total match
 * count in this header, since the response body itself may be a bounded
 * page of a much larger result - see SubdomainController/FindingController.
 * Falls back to the page's own length if the header is missing/unparseable,
 * so a caller that doesn't care about the true total still gets a sane value.
 */
export function totalCountFromResponse(res: Response, fallbackCount: number): number {
  const header = res.headers.get("X-Total-Count");
  const parsed = header ? Number(header) : NaN;
  return Number.isFinite(parsed) ? parsed : fallbackCount;
}

/**
 * Reads a specific error message from a failed response's {message} JSON body - the pattern
 * every controller that needs to tell the caller *why* a request was rejected uses (see
 * SlackIntegrationController's own ErrorMessageResponse javadoc for why this can't just be a
 * ResponseStatusException's reason: this app's default error handler never puts that in the
 * body). Falls back to a generic message for endpoints that don't return one (a bare 500, a
 * network failure, or a controller that hasn't been given a specific message yet).
 */
export async function readErrorMessage(res: Response, fallback: string): Promise<string> {
  const body = await res.json().catch(() => undefined);
  return (body && typeof body.message === "string" && body.message) || fallback;
}
