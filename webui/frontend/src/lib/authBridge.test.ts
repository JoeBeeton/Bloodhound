import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { UserSummary } from "./types";

// authBridge holds module-level state (`bootstrapped`, `state`) that persists across imports within
// one test file - vi.resetModules() + a fresh dynamic import per test gives each test a clean bridge,
// matching how a real page load only ever bootstraps once.
async function freshBridge() {
  vi.resetModules();
  const authClient = await import("./authClient");
  const bridge = await import("./authBridge");
  return { authClient, bridge };
}

const user: UserSummary = {
  id: "u1",
  email: "test@example.com",
  displayName: "Test User",
  role: "VIEWER",
  organizationId: "org1",
};

vi.mock("./authClient", () => ({
  refresh: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  ssoExchange: vi.fn(),
}));

describe("authBridge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("starts in the loading state before bootstrap runs", async () => {
    const { bridge } = await freshBridge();
    expect(bridge.getState().status).toBe("loading");
  });

  it("bootstrap transitions to authenticated when refresh succeeds", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.refresh).mockResolvedValue({ accessToken: "tok", expiresIn: 900, user });

    await bridge.bootstrap();

    expect(bridge.getState()).toEqual({ status: "authenticated", accessToken: "tok", user });
  });

  it("bootstrap transitions to unauthenticated when refresh returns null (no valid session)", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.refresh).mockResolvedValue(null);

    await bridge.bootstrap();

    expect(bridge.getState()).toEqual({ status: "unauthenticated", accessToken: null, user: null });
  });

  it("bootstrap transitions to unauthenticated when refresh throws", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.refresh).mockRejectedValue(new Error("network error"));

    await bridge.bootstrap();

    expect(bridge.getState()).toEqual({ status: "unauthenticated", accessToken: null, user: null });
  });

  it("bootstrap only calls authClient.refresh once even if invoked multiple times", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.refresh).mockResolvedValue({ accessToken: "tok", expiresIn: 900, user });

    await Promise.all([bridge.bootstrap(), bridge.bootstrap(), bridge.bootstrap()]);

    expect(authClient.refresh).toHaveBeenCalledTimes(1);
  });

  it("login sets authenticated state from the login response", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.login).mockResolvedValue({ accessToken: "tok", expiresIn: 900, user });

    await bridge.login("test@example.com", "hunter2");

    expect(bridge.getState()).toEqual({ status: "authenticated", accessToken: "tok", user });
    expect(authClient.login).toHaveBeenCalledWith("test@example.com", "hunter2");
  });

  it("logout clears state to unauthenticated even if the server call fails", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.logout).mockRejectedValue(new Error("network error"));

    await bridge.logout();

    expect(bridge.getState()).toEqual({ status: "unauthenticated", accessToken: null, user: null });
  });

  it("silentRefresh updates state and returns the new token on success", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.refresh).mockResolvedValue({ accessToken: "new-tok", expiresIn: 900, user });

    const token = await bridge.silentRefresh();

    expect(token).toBe("new-tok");
    expect(bridge.getState()).toEqual({ status: "authenticated", accessToken: "new-tok", user });
  });

  it("silentRefresh clears state and returns null when the session can't be renewed", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.refresh).mockResolvedValue(null);

    const token = await bridge.silentRefresh();

    expect(token).toBeNull();
    expect(bridge.getState()).toEqual({ status: "unauthenticated", accessToken: null, user: null });
  });

  it("subscribe notifies listeners on every state change, and unsubscribe stops future notifications", async () => {
    const { authClient, bridge } = await freshBridge();
    vi.mocked(authClient.login).mockResolvedValue({ accessToken: "tok", expiresIn: 900, user });
    const listener = vi.fn();
    const unsubscribe = bridge.subscribe(listener);

    await bridge.login("test@example.com", "hunter2");
    expect(listener).toHaveBeenCalledTimes(1);

    unsubscribe();
    await bridge.logout();
    expect(listener).toHaveBeenCalledTimes(1);
  });
});
