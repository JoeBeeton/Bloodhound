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
