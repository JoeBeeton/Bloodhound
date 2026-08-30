import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { AdminScimPage, statusDisplay } from "./AdminScimPage";

interface ScimTokenSummary {
  id: string;
  label: string;
  createdAt: string;
  revokedAt: string | null;
  expiresAt: string | null;
  expired: boolean;
}

function token(overrides: Partial<ScimTokenSummary> = {}): ScimTokenSummary {
  return {
    id: "t1",
    label: "Okta",
    createdAt: "2026-01-01T00:00:00Z",
    revokedAt: null,
    expiresAt: null,
    expired: false,
    ...overrides,
  };
}

const NOW = new Date("2026-05-01T00:00:00Z").getTime();

describe("AdminScimPage statusDisplay", () => {
  it("shows 'Active · never expires' for the deliberate default (no expiresAt at all)", () => {
    // Unlike ApiKeysPage, this is the expected default for a continuous directory-sync
    // credential, not a fallback for missing data - see V44__scim_token_expiry.sql.
    expect(statusDisplay(token(), NOW)).toEqual({ label: "Active · never expires", className: "text-neon-cyan" });
  });

  it("shows a plain 'Active' when an explicit expiry is comfortably in the future", () => {
    expect(statusDisplay(token({ expiresAt: "2026-12-01T00:00:00Z" }), NOW)).toEqual({
      label: "Active",
      className: "text-neon-cyan",
    });
  });

  it("warns in amber once an explicit expiry is within 14 days", () => {
    const status = statusDisplay(token({ expiresAt: "2026-05-10T00:00:00Z" }), NOW);
    expect(status.label).toBe("Active · 9d left");
    expect(status.className).toBe("text-neon-amber");
  });

  it("shows 'Revoked' regardless of expiry (including a token that never expires)", () => {
    expect(statusDisplay(token({ revokedAt: "2026-04-15T00:00:00Z" }), NOW)).toEqual({
      label: "Revoked",
      className: "text-slate-500",
    });
  });

  it("shows 'Expired' rather than a negative day count once past an explicit expiry", () => {
    expect(statusDisplay(token({ expired: true, expiresAt: "2026-04-01T00:00:00Z" }), NOW)).toEqual({
      label: "Expired",
      className: "text-neon-amber",
    });
  });
});

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/AdminSubNav", () => ({ AdminSubNav: () => <div /> }));
vi.mock("../lib/useAuth", () => ({ useAuth: () => ({ user: { organizationId: "org-1", role: "ADMIN" } }) }));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminScimPage />
    </QueryClientProvider>,
  );
}

describe("AdminScimPage - revoke confirmation and failure surfacing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows no error before revoking", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse({ scimBaseUrl: "https://app/scim/v2", tokens: [token()] }),
    );

    renderPage();

    await screen.findByText("Okta", {}, { timeout: 5000 });
    expect(screen.queryByText(/failed to revoke/i)).not.toBeInTheDocument();
  });

  it("clicking 'Revoke' opens a confirmation modal without firing the request until confirmed", async () => {
    // A security/AppSec review found this page was the one credential-revoke flow in the app
    // that fired straight from the row's onClick with zero confirmation - a stray click on this
    // table's only per-row control could otherwise silently break an org's live IdP-driven user
    // provisioning. Mirrors ApiKeysPage's own confirmation modal for the identical shape of risk.
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ scimBaseUrl: "https://app/scim/v2", tokens: [token()] }));

    renderPage();
    await screen.findByText("Okta", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Revoke" }));

    expect(await screen.findByText(/cannot be undone/i)).toBeInTheDocument();
    // Only the initial list-load GET has happened so far - no DELETE fired just from opening the modal.
    expect(mockedApiFetch).toHaveBeenCalledTimes(1);
  });

  it("Cancel closes the confirmation without revoking anything", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ scimBaseUrl: "https://app/scim/v2", tokens: [token()] }));

    renderPage();
    await screen.findByText("Okta", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByText(/cannot be undone/i)).not.toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(1);
  });

  it("confirming revokes the token and refetches the list", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse({ scimBaseUrl: "https://app/scim/v2", tokens: [token()] })) // list
      .mockResolvedValueOnce(jsonResponse(undefined)) // DELETE
      .mockResolvedValueOnce(jsonResponse({ scimBaseUrl: "https://app/scim/v2", tokens: [] })); // refetch

    renderPage();
    await screen.findByText("Okta", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await user.click(screen.getByRole("button", { name: "Revoke token" }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/scim-tokens/t1", { method: "DELETE" }));
    await waitFor(() => expect(screen.queryByText(/cannot be undone/i)).not.toBeInTheDocument());
  });

  it("shows an error message inside the modal when revoking fails, and does not close it", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse({ scimBaseUrl: "https://app/scim/v2", tokens: [token()] })) // list
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 })); // DELETE fails

    renderPage();
    await screen.findByText("Okta", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await user.click(screen.getByRole("button", { name: "Revoke token" }));

    expect(
      await screen.findByText("Failed to revoke token. Try again.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(screen.getByText(/cannot be undone/i)).toBeInTheDocument(); // modal stays open
  });
});
