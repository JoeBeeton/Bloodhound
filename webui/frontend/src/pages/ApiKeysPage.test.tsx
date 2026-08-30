import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { ApiKeysPage, statusDisplay, type ApiKeySummary } from "./ApiKeysPage";

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

    // Revoking is permanent and breaks any integration still using the key immediately - the row
    // button only opens a confirmation modal now, it doesn't fire the DELETE by itself.
    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await user.click(await screen.findByRole("button", { name: /revoke key/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/api-keys/k1", { method: "DELETE" }), { timeout: 5000 });
  });

  it("clicking Revoke opens a confirmation modal without firing the DELETE until confirmed", async () => {
    const user = userEvent.setup();
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
      ]),
    );

    renderPage();
    await screen.findByText("CI integration", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Revoke" }));

    expect(await screen.findByText(/cannot be undone/i)).toBeInTheDocument();
    // Only the list-load GET has happened so far - no DELETE fired just from opening the modal.
    expect(mockedApiFetch).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText(/cannot be undone/i)).not.toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(1);
  });
});

function key(overrides: Partial<ApiKeySummary> = {}): ApiKeySummary {
  return {
    id: "k1",
    label: "test key",
    keyPrefix: "bhk_abc123",
    createdAt: "2026-01-01T00:00:00Z",
    expiresAt: "2026-06-01T00:00:00Z",
    lastUsedAt: null,
    revoked: false,
    expired: false,
    ...overrides,
  };
}

const NOW = new Date("2026-05-01T00:00:00Z").getTime();

describe("statusDisplay", () => {
  it("shows a plain 'Active' when expiry is comfortably in the future", () => {
    const status = statusDisplay(key({ expiresAt: "2026-12-01T00:00:00Z" }), NOW);
    expect(status).toEqual({ label: "Active", className: "text-neon-cyan" });
  });

  it("warns in amber once expiry is within 14 days", () => {
    const status = statusDisplay(key({ expiresAt: "2026-05-10T00:00:00Z" }), NOW);
    expect(status.label).toBe("Active · 9d left");
    expect(status.className).toBe("text-neon-amber");
  });

  it("shows 'Revoked' regardless of expiry proximity", () => {
    const status = statusDisplay(key({ revoked: true, expiresAt: "2026-05-02T00:00:00Z" }), NOW);
    expect(status).toEqual({ label: "Revoked", className: "text-slate-500" });
  });

  it("shows 'Expired' rather than a negative day count once past expiry", () => {
    const status = statusDisplay(key({ expired: true, expiresAt: "2026-04-01T00:00:00Z" }), NOW);
    expect(status).toEqual({ label: "Expired", className: "text-neon-amber" });
  });
});
