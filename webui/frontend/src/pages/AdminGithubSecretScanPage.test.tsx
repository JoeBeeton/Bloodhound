import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { AdminGithubSecretScanPage } from "./AdminGithubSecretScanPage";

vi.mock("../lib/apiClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/apiClient")>()),
  apiFetch: vi.fn(),
}));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/AdminSubNav", () => ({ AdminSubNav: () => <div /> }));
vi.mock("../lib/useAuth", () => ({
  useAuth: () => ({ status: "authenticated", user: { organizationId: "org-1", role: "ADMIN" } }),
}));

const mockedApiFetch = vi.mocked(apiFetch);
const REAL_TOKEN = "ghp_" + "realtokenvalue1234567890abcdef";

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body, text: async () => "" } as Response;
}

function noneConfiguredResponse() {
  return { ok: true, status: 204, json: async () => null, text: async () => "" } as Response;
}

function existingIntegration(overrides: Record<string, unknown> = {}) {
  return { enabled: true, updatedAt: "2026-01-01T00:00:00Z", ...overrides };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminGithubSecretScanPage />
    </QueryClientProvider>,
  );
}

describe("AdminGithubSecretScanPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the token input (not a masked value) when nothing is configured yet", async () => {
    mockedApiFetch.mockResolvedValueOnce(noneConfiguredResponse());

    renderPage();

    expect(await screen.findByPlaceholderText(/ghp_/i)).toBeInTheDocument();
    expect(screen.queryByText(/configured ·/i)).not.toBeInTheDocument();
  });

  it("shows a plain 'configured' line, never any part of the token, once one is saved", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(existingIntegration()));

    renderPage();

    const configuredLine = await screen.findByText(/configured ·/i);
    expect(configuredLine.textContent).not.toContain("ghp_");
    expect(screen.queryByPlaceholderText(/ghp_/i)).not.toBeInTheDocument();
  });

  it("saving a new token sends it to the PUT endpoint", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(noneConfiguredResponse())
      .mockResolvedValueOnce(jsonResponse(existingIntegration()))
      .mockResolvedValueOnce(jsonResponse(existingIntegration()));

    renderPage();
    const input = await screen.findByPlaceholderText(/ghp_/i);
    await user.type(input, REAL_TOKEN);
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/github-secret-search-integration", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: REAL_TOKEN, enabled: true }),
      }),
    );
  });

  it("toggling only 'enabled' (without replacing the token) sends a blank token", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration({ enabled: true })))
      .mockResolvedValueOnce(jsonResponse(existingIntegration({ enabled: false })))
      .mockResolvedValueOnce(jsonResponse(existingIntegration({ enabled: false })));

    renderPage();
    await screen.findByText(/configured ·/i);
    await user.click(screen.getByLabelText("Enabled"));
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/github-secret-search-integration", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: "", enabled: false }),
      }),
    );
  });

  it("rejects a too-short token before it's ever sent", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(noneConfiguredResponse());

    renderPage();
    const input = await screen.findByPlaceholderText(/ghp_/i);
    await user.type(input, "short");

    expect(screen.getByText(/too short to be a real github personal access token/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("'Replace' switches back to the input field", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(existingIntegration()));

    renderPage();
    await screen.findByText(/configured ·/i);
    await user.click(screen.getByRole("button", { name: "Replace" }));

    expect(screen.getByPlaceholderText(/ghp_/i)).toBeInTheDocument();
  });

  it("clicking 'Remove integration' opens a confirmation modal without deleting anything yet", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(existingIntegration()));
    const user = userEvent.setup();

    renderPage();
    await screen.findByText(/configured ·/i);
    await user.click(screen.getByRole("button", { name: "Remove integration" }));

    expect(await screen.findByText(/isn't retrievable once removed/i)).toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(1);
  });

  it("confirming removes the integration and resets the form", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration()))
      .mockResolvedValueOnce(jsonResponse(undefined))
      .mockResolvedValueOnce(noneConfiguredResponse());

    renderPage();
    await screen.findByText(/configured ·/i);
    await user.click(screen.getByRole("button", { name: "Remove integration" }));
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Remove integration" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/github-secret-search-integration", {
        method: "DELETE",
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(3));
  });

  it("warns once a fresh token is typed - the one thing here that isn't retrievable if lost", async () => {
    const user = userEvent.setup();
    const addSpy = vi.spyOn(window, "addEventListener");
    mockedApiFetch.mockResolvedValueOnce(noneConfiguredResponse());

    renderPage();
    const input = await screen.findByPlaceholderText(/ghp_/i);
    expect(addSpy).not.toHaveBeenCalledWith("beforeunload", expect.any(Function));

    await user.type(input, REAL_TOKEN);

    const call = addSpy.mock.calls.filter(([type]) => type === "beforeunload").at(-1);
    expect(call).toBeDefined();
    expect(screen.getByText("Unsaved changes.")).toBeInTheDocument();
  });
});
