import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch, totalCountFromResponse } from "./apiClient";
import * as bridge from "./authBridge";

describe("totalCountFromResponse", () => {
  function responseWithHeader(value: string | null): Response {
    const headers = new Headers();
    if (value !== null) headers.set("X-Total-Count", value);
    return new Response(null, { headers });
  }

  it("parses a numeric X-Total-Count header", () => {
    expect(totalCountFromResponse(responseWithHeader("57107"), 200)).toBe(57107);
  });

  it("falls back to the provided count when the header is missing", () => {
    expect(totalCountFromResponse(responseWithHeader(null), 42)).toBe(42);
  });

  it("falls back to the provided count when the header is unparseable", () => {
    expect(totalCountFromResponse(responseWithHeader("not-a-number"), 42)).toBe(42);
  });

  it("treats an empty-string header as unparseable, not zero", () => {
    expect(totalCountFromResponse(responseWithHeader(""), 42)).toBe(42);
  });

  it("accepts zero as a genuine parsed value, not a falsy fallback trigger", () => {
    expect(totalCountFromResponse(responseWithHeader("0"), 999)).toBe(0);
  });
});

describe("apiFetch", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("attaches the bearer token from the auth bridge when present", async () => {
    vi.spyOn(bridge, "getState").mockReturnValue({
      status: "authenticated",
      accessToken: "test-token-123",
      user: null,
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));

    await apiFetch("/api/v1/targets");

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get("Authorization")).toBe("Bearer test-token-123");
  });

  it("sends no Authorization header when there is no token", async () => {
    vi.spyOn(bridge, "getState").mockReturnValue({ status: "unauthenticated", accessToken: null, user: null });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));

    await apiFetch("/api/v1/targets");

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.has("Authorization")).toBe(false);
  });

  it("on a 401, attempts a silent refresh and retries once with the new token", async () => {
    vi.spyOn(bridge, "getState")
      .mockReturnValueOnce({ status: "authenticated", accessToken: "stale-token", user: null })
      .mockReturnValueOnce({ status: "authenticated", accessToken: "fresh-token", user: null });
    vi.spyOn(bridge, "silentRefresh").mockResolvedValue("fresh-token");
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }));

    const result = await apiFetch("/api/v1/targets");

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(result.status).toBe(200);
    const [, secondInit] = fetchSpy.mock.calls[1];
    expect(new Headers(secondInit?.headers).get("Authorization")).toBe("Bearer fresh-token");
  });

  it("on a 401 with a failed silent refresh, returns the original 401 without retrying", async () => {
    vi.spyOn(bridge, "getState").mockReturnValue({ status: "authenticated", accessToken: "stale-token", user: null });
    vi.spyOn(bridge, "silentRefresh").mockResolvedValue(null);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(null, { status: 401 }));

    const result = await apiFetch("/api/v1/targets");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(result.status).toBe(401);
  });

  it("always sends credentials: include, for the httpOnly refresh cookie", async () => {
    vi.spyOn(bridge, "getState").mockReturnValue({ status: "unauthenticated", accessToken: null, user: null });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));

    await apiFetch("/api/v1/targets");

    const [, init] = fetchSpy.mock.calls[0];
    expect(init?.credentials).toBe("include");
  });
});
