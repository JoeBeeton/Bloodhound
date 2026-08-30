import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { AdminSlackPage } from "./AdminSlackPage";

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

function existingIntegration(overrides: Record<string, unknown> = {}) {
  return {
    webhookUrlMasked: "https://hooks.slack.com/services/T000/B000/***",
    enabled: true,
    notificationTypes: ["NEW_FINDINGS"],
    ownTargetsOnly: false,
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminSlackPage />
    </QueryClientProvider>,
  );
}

describe("AdminSlackPage - test-send", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not offer a test-send button when no integration is configured yet", async () => {
    mockedApiFetch.mockResolvedValueOnce({ ok: true, status: 204, json: async () => null, text: async () => "" } as Response);

    renderPage();
    await screen.findByPlaceholderText(/hooks\.slack\.com/i);

    expect(screen.queryByRole("button", { name: /send test message/i })).not.toBeInTheDocument();
  });

  it("a successful test send shows the confirmation message", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration())) // initial load
      .mockResolvedValueOnce(jsonResponse({ success: true, detail: null })); // test send

    renderPage();
    const testBtn = await screen.findByRole("button", { name: /send test message/i });

    await user.click(testBtn);

    expect(await screen.findByText(/test message sent/i)).toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenLastCalledWith("/api/v1/orgs/org-1/slack-integration/test", { method: "POST" });
  });

  it("a failed delivery shows the failure detail from the server", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration()))
      .mockResolvedValueOnce(jsonResponse({ success: false, detail: "Slack responded with HTTP 404" }));

    renderPage();
    const testBtn = await screen.findByRole("button", { name: /send test message/i });

    await user.click(testBtn);

    expect(await screen.findByText(/delivery failed: slack responded with http 404/i)).toBeInTheDocument();
  });

  it("a request-level failure (e.g. no webhook configured) shows the server's error message", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration()))
      .mockResolvedValueOnce({ ok: false, status: 400, text: async () => "No Slack webhook configured yet - save one first." } as Response);

    renderPage();
    const testBtn = await screen.findByRole("button", { name: /send test message/i });

    await user.click(testBtn);

    expect(await screen.findByText(/no slack webhook configured yet/i)).toBeInTheDocument();
  });

  it("disables the test-send button while the webhook field is being edited", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(existingIntegration()));

    renderPage();
    const testBtn = await screen.findByRole("button", { name: /send test message/i });
    expect(testBtn).toBeEnabled();

    await user.click(screen.getByRole("button", { name: "Change" }));
    expect(testBtn).toBeDisabled();
  });

  it("clears a previous test result once the webhook is changed", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration()))
      .mockResolvedValueOnce(jsonResponse({ success: true, detail: null }));

    renderPage();
    const testBtn = await screen.findByRole("button", { name: /send test message/i });
    await user.click(testBtn);
    await screen.findByText(/test message sent/i);

    await user.click(screen.getByRole("button", { name: "Change" }));

    await waitFor(() => expect(screen.queryByText(/test message sent/i)).not.toBeInTheDocument());
  });

  it("shows an error message when removing the integration fails", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration())) // initial load
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 })); // DELETE fails

    renderPage();
    await screen.findByRole("button", { name: /send test message/i });

    await user.click(screen.getByRole("button", { name: "Remove integration" }));

    expect(
      await screen.findByText("Failed to remove the integration. Try again.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
  });
});
