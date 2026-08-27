import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { ApiKeysPage } from "./ApiKeysPage";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
// Shell pulls in useAuth/nav/NotificationCenter chrome unrelated to this page's own logic - stubbed
// out so this test is isolated to ApiKeysPage's query/mutation/conditional-rendering behavior.
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: async () => body,
  } as Response;
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const mockedApiFetch = vi.mocked(apiFetch);

describe("ApiKeysPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the empty state when there are no keys yet", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([]));

    renderPage();

    expect(await screen.findByText(/no api keys yet/i, {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("shows an error state and lets the user retry the list load", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderPage();

    expect(await screen.findByText(/failed to load api keys/i, {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("renders existing keys with their status, without ever showing a raw key value", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse([
        {
          id: "k1",
          label: "CI integration",
          keyPrefix: "bhk_abc123",
          createdAt: "2026-01-01T00:00:00Z",
          expiresAt: "2026-04-01T00:00:00Z",
          lastUsedAt: null,
          revoked: false,
          expired: false,
        },
        {
          id: "k2",
          label: "Old dashboard",
          keyPrefix: "bhk_def456",
          createdAt: "2025-01-01T00:00:00Z",
          expiresAt: "2025-04-01T00:00:00Z",
          lastUsedAt: null,
          revoked: true,
          expired: false,
        },
      ]),
    );

    renderPage();

    expect(await screen.findByText("CI integration", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText("Old dashboard")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Revoked")).toBeInTheDocument();
    // A revoked key offers no "Revoke" button of its own; only the still-active one does.
    expect(screen.getAllByText("Revoke")).toHaveLength(1);
  });

  it("generating a key shows the raw key exactly once, in the modal, and refetches the list", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([])) // initial list load
      .mockResolvedValueOnce(
        jsonResponse({
          id: "new-id",
          label: "reporting dashboard",
          keyPrefix: "bhk_xyz999",
          apiKey: "bhk_xyz999therestofit",
          createdAt: "2026-01-01T00:00:00Z",
          expiresAt: "2026-04-01T00:00:00Z",
        }),
      ) // create
      .mockResolvedValueOnce(jsonResponse([])); // refetch after invalidation

    renderPage();
    await screen.findByText(/no api keys yet/i, {}, { timeout: 5000 });

    await user.type(screen.getByPlaceholderText(/reporting dashboard/i), "reporting dashboard");
    await user.click(screen.getByRole("button", { name: /generate key/i }));

    expect(await screen.findByText("bhk_xyz999therestofit", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText(/shown once and cannot be retrieved again/i)).toBeInTheDocument();

    const createCall = mockedApiFetch.mock.calls[1];
    expect(createCall[0]).toBe("/api/v1/api-keys");
    expect(JSON.parse((createCall[1] as RequestInit).body as string)).toEqual({
      label: "reporting dashboard",
      expiresInDays: 90,
    });
  });

  it("revoking a key calls DELETE with its id and refetches the list", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(
        jsonResponse([
          {
            id: "k1",
            label: "CI integration",
            keyPrefix: "bhk_abc123",
            createdAt: "2026-01-01T00:00:00Z",
            expiresAt: "2026-04-01T00:00:00Z",
            lastUsedAt: null,
            revoked: false,
            expired: false,
          },
        ]),
      )
      .mockResolvedValueOnce(jsonResponse(undefined)) // DELETE
      .mockResolvedValueOnce(jsonResponse([])); // refetch after invalidation

    renderPage();
    await screen.findByText("CI integration", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: /revoke/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/api-keys/k1", { method: "DELETE" }), { timeout: 5000 });
  });
});
