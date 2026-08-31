import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { NotificationCenter } from "./NotificationCenter";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function notification(overrides: Record<string, unknown> = {}) {
  return {
    id: "n1",
    type: "NEW_FINDINGS",
    severity: "CRITICAL",
    title: "New critical finding",
    message: "example.com has a new critical finding.",
    targetId: "t1",
    targetHostname: "example.com",
    scanRunId: "run1",
    isRead: false,
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderCenter() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <NotificationCenter />
      </QueryClientProvider>
    </MemoryRouter>,
  );
  return queryClient;
}

/**
 * Drives the exact same toast-triggering path a real background poll would (the effect watches
 * [query.data], not how it changed) without touching refetchInterval/fake timers at all - simpler
 * and avoids react-query's own internal refetch scheduling outliving a test when mixed with fake
 * timers (a real, separately-diagnosed flakiness class earlier this session in a different file).
 * A real baseline notification on the first load is required first: the watermark-diffing effect
 * treats "no prior notification at all" as nothing to compare a later one against (see the
 * component's own effect), so a fresh notification pushed in before a baseline exists would never
 * be recognized as new.
 */
async function establishBaselineThenPushFresh(queryClient: QueryClient, freshOverrides: Record<string, unknown>) {
  await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(1));
  await screen.findByText((_, el) => el?.textContent === "1"); // the unread badge, proof the first response was applied

  const fresh = notification({ createdAt: "2026-01-02T00:00:00Z", ...freshOverrides });
  act(() => {
    queryClient.setQueryData(["notifications"], { notifications: [fresh], unreadCount: 1 });
  });
}

describe("NotificationCenter - toasts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not toast the existing backlog on first load", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ notifications: [notification()], unreadCount: 1 }));

    renderCenter();
    await screen.findByLabelText("Notifications");
    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(1));

    expect(screen.queryByText("New critical finding")).not.toBeInTheDocument();
  });

  it("a notification newer than the watermark shows as a toast in a live region, reachable by keyboard", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse({ notifications: [notification({ id: "baseline", createdAt: "2025-01-01T00:00:00Z" })], unreadCount: 1 }),
    );
    const queryClient = renderCenter();
    await establishBaselineThenPushFresh(queryClient, { id: "n2" });

    const toastButton = await screen.findByRole("button", { name: /new critical finding/i });
    // The button is a real, focusable element - the actual accessibility contract this test
    // guards (a bare div-with-onClick, the pre-fix shape, would never match getByRole("button")).
    expect(toastButton).toBeInTheDocument();

    // The live region wrapping it: a screen reader announces content added inside this, unlike
    // the pre-fix plain div.
    expect(toastButton.closest('[aria-live="polite"]')).not.toBeNull();

    expect(screen.getByRole("button", { name: "Dismiss notification" })).toBeInTheDocument();
  });

  it("dismissing a toast removes it without navigating", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse({ notifications: [notification({ id: "baseline", createdAt: "2025-01-01T00:00:00Z" })], unreadCount: 1 }),
    );
    const queryClient = renderCenter();
    await establishBaselineThenPushFresh(queryClient, { id: "n3" });
    await screen.findByRole("button", { name: /new critical finding/i });
    const callsBeforeDismiss = mockedApiFetch.mock.calls.length;

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Dismiss notification" }));

    await waitFor(() => expect(screen.queryByRole("button", { name: /new critical finding/i })).not.toBeInTheDocument());
    // Dismissing must not have marked it read or navigated - no extra apiFetch call beyond
    // whatever had already happened by that point.
    expect(mockedApiFetch.mock.calls.length).toBe(callsBeforeDismiss);
  });
});
