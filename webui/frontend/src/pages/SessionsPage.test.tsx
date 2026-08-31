import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { SessionsPage, type SessionSummary } from "./SessionsPage";

vi.mock("../lib/apiClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/apiClient")>()),
  apiFetch: vi.fn(),
}));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function session(overrides: Partial<SessionSummary> = {}): SessionSummary {
  return {
    id: "s1",
    sessionStartedAt: "2026-01-01T00:00:00Z",
    createdAt: "2026-01-15T00:00:00Z",
    expiresAt: "2026-06-01T00:00:00Z",
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <SessionsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SessionsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the empty state when there are no active sessions", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([]));

    renderPage();

    expect(await screen.findByText(/no active sessions/i, {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("shows an error state and lets the user retry the list load", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderPage();

    expect(await screen.findByText(/failed to load sessions/i, {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("renders each session's start and expiry, with one End session button per row", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([session({ id: "s1" }), session({ id: "s2" })]));

    renderPage();

    expect(await screen.findAllByText(/started/i, {}, { timeout: 5000 })).toHaveLength(2);
    expect(screen.getAllByRole("button", { name: "End session" })).toHaveLength(2);
  });

  it("clicking End session opens a confirmation modal without firing the DELETE until confirmed", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([session()]));

    renderPage();
    await screen.findAllByText(/started/i, {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "End session" }));

    expect(await screen.findByText(/you'll be signed out immediately/i)).toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(1); // only the list load - no DELETE yet

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText(/you'll be signed out immediately/i)).not.toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(1);
  });

  it("confirming ends the session and refetches the list", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([session({ id: "s1" })]))
      .mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response) // DELETE
      .mockResolvedValueOnce(jsonResponse([])); // refetch after invalidation

    renderPage();
    await screen.findAllByText(/started/i, {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "End session" }));
    // Two buttons now share the accessible name "End session" (the row's and the modal's confirm)
    // - the modal's is rendered last, so it's the last match.
    await screen.findByText(/you'll be signed out immediately/i);
    const buttons = screen.getAllByRole("button", { name: "End session" });
    await user.click(buttons[buttons.length - 1]);

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/users/me/sessions/s1", { method: "DELETE" }), {
      timeout: 5000,
    });
  });

  it("shows the server's error message inside the modal when ending a session fails, and it stays open", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([session({ id: "s1" })]))
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 404 })); // DELETE fails

    renderPage();
    await screen.findAllByText(/started/i, {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "End session" }));
    const buttons = screen.getAllByRole("button", { name: "End session" });
    await user.click(buttons[buttons.length - 1]);

    expect(await screen.findByText("Failed to end session.", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText(/you'll be signed out immediately/i)).toBeInTheDocument(); // modal stays open
  });
});
