import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { AdminMcpPage } from "./AdminMcpPage";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/AdminSubNav", () => ({ AdminSubNav: () => <div /> }));
vi.mock("../lib/useAuth", () => ({
  useAuth: () => ({ status: "authenticated", user: { organizationId: "org-1", role: "ADMIN" } }),
}));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body, text: async () => "" } as Response;
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminMcpPage />
    </QueryClientProvider>,
  );
}

describe("AdminMcpPage - signing key restart notice", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("explains why a previously-connected agent needs to reconnect, with the actual generation time", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse({ mcpEnabled: true, mcpSigningKeyGeneratedAt: "2026-08-31T02:00:00Z" }),
    );

    renderPage();

    expect(await screen.findByText(/every central-server restart generates a new one/i)).toBeInTheDocument();
    expect(screen.getByText(new RegExp(new Date("2026-08-31T02:00:00Z").toLocaleString().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))).toBeInTheDocument();
  });

  it("does not show the notice before the settings have loaded", () => {
    mockedApiFetch.mockReturnValueOnce(new Promise(() => {})); // never resolves

    renderPage();

    expect(screen.queryByText(/every central-server restart generates a new one/i)).not.toBeInTheDocument();
  });

  it("saving still round-trips mcpEnabled only, unaffected by the added read-only field", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse({ mcpEnabled: true, mcpSigningKeyGeneratedAt: "2026-08-31T02:00:00Z" }))
      .mockResolvedValueOnce(jsonResponse({ mcpEnabled: false, mcpSigningKeyGeneratedAt: "2026-08-31T02:00:00Z" }));

    renderPage();
    await screen.findByText(/every central-server restart generates a new one/i);

    await user.click(screen.getByLabelText(/mcp server enabled for this organization/i));
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mcpEnabled: false }),
      }),
    );
  });
});
