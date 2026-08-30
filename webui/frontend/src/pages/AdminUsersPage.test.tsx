import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { AdminUsersPage } from "./AdminUsersPage";
import type { AdminUser } from "../lib/types";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/AdminSubNav", () => ({ AdminSubNav: () => <div /> }));
vi.mock("../lib/useAuth", () => ({
  useAuth: () => ({ user: { id: "self", organizationId: "org-1", role: "ADMIN" } }),
}));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function adminUser(overrides: Partial<AdminUser> = {}): AdminUser {
  return {
    id: "u1",
    email: "alice@example.com",
    displayName: "Alice",
    role: "VIEWER",
    status: "ACTIVE",
    organizationId: "org-1",
    mcpEnabled: false,
    identitySource: "LOCAL",
    lastLoginAt: null,
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminUsersPage />
    </QueryClientProvider>,
  );
}

describe("AdminUsersPage - update failure surfacing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows no error message before any edit is attempted", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([adminUser()]));

    renderPage();

    await screen.findByText("alice@example.com", {}, { timeout: 5000 });
    expect(screen.queryByText(/failed to update/i)).not.toBeInTheDocument();
  });

  it("a failed role change shows 'Failed to update role for <email>'", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([adminUser()])) // list
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 })); // PATCH role

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    await user.selectOptions(screen.getByDisplayValue("VIEWER"), "ADMIN");

    expect(
      await screen.findByText("Failed to update role for alice@example.com. Try again.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
  });

  it("a failed status change shows 'Failed to update status for <email>'", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([adminUser()]))
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    await user.selectOptions(screen.getByDisplayValue("ACTIVE"), "DISABLED");

    expect(
      await screen.findByText("Failed to update status for alice@example.com. Try again.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
  });

  it("a failed MCP-access toggle shows 'Failed to update MCP access for <email>'", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([adminUser()]))
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    await user.click(screen.getByTitle(/enable mcp access/i));

    expect(
      await screen.findByText("Failed to update MCP access for alice@example.com. Try again.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
  });

  it("a successful edit after a prior failure clears the error message", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([adminUser()])) // list
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 })) // PATCH role fails
      .mockResolvedValueOnce(jsonResponse({ ...adminUser(), status: "DISABLED" })) // PATCH status succeeds
      .mockResolvedValueOnce(jsonResponse([adminUser({ status: "DISABLED" })])); // refetch after invalidation

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    await user.selectOptions(screen.getByDisplayValue("VIEWER"), "ADMIN");
    await screen.findByText(/failed to update role/i, {}, { timeout: 5000 });

    await user.selectOptions(screen.getByDisplayValue("ACTIVE"), "DISABLED");

    await waitFor(() => expect(screen.queryByText(/failed to update/i)).not.toBeInTheDocument());
  });
});
