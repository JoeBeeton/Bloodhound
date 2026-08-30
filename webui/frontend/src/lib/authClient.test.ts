import { afterEach, describe, expect, it, vi } from "vitest";
import { login } from "./authClient";

function mockResponse(status: number, headers: Record<string, string> = {}): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
    json: () => Promise.resolve({}),
  } as Response;
}

describe("authClient.login", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("401 shows a generic invalid-credentials message, not the email-enumerating one central-server itself avoids", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse(401)));

    await expect(login("u@example.com", "wrong")).rejects.toThrow("Invalid email or password.");
  });

  it("429 with a Retry-After header shows a specific, actionable wait time - not the generic error", async () => {
    // The actual point of this test: a product review found a rate-limited login previously
    // showed the exact same "Something went wrong. Try again." message as any other failure,
    // which is actively counterproductive - it reads as transient and invites immediately
    // retrying the exact thing being throttled, instead of telling the user how long to wait.
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse(429, { "Retry-After": "645" })));

    await expect(login("u@example.com", "wrong")).rejects.toThrow("Too many failed attempts. Try again in 11 minutes.");
  });

  it("429 with no Retry-After header still shows the rate-limit message, falling back to a vague duration", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse(429)));

    await expect(login("u@example.com", "wrong")).rejects.toThrow("Too many failed attempts. Try again in a few minutes.");
  });

  it("other failures (5xx, network-adjacent) keep the generic message", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse(500)));

    await expect(login("u@example.com", "wrong")).rejects.toThrow("Something went wrong. Try again.");
  });
});
