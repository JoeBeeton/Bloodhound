import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
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

  it("clicking 'Remove integration' opens a confirmation modal without deleting anything yet", async () => {
    // A security/AppSec review found this was the last credential-revoke-shaped action in the
    // app that still fired straight from onClick with zero confirmation, the same "one stray
    // click, no undo" bug ApiKeysPage's and AdminScimPage's own revoke flows were already fixed
    // against - the webhook URL isn't retrievable once removed, so undoing this means generating
    // a brand new one from Slack's own admin UI, not just re-toggling a switch.
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(existingIntegration()));

    renderPage();
    await screen.findByRole("button", { name: /send test message/i });

    await user.click(screen.getByRole("button", { name: "Remove integration" }));

    expect(await screen.findByText(/isn't retrievable once removed/i)).toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(1); // only the initial load - no DELETE fired yet
  });

  it("Cancel closes the confirmation without removing anything", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(existingIntegration()));

    renderPage();
    await screen.findByRole("button", { name: /send test message/i });

    await user.click(screen.getByRole("button", { name: "Remove integration" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByText(/isn't retrievable once removed/i)).not.toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(1);
  });

  it("shows an error message inside the modal when removing the integration fails, and it stays open", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration())) // initial load
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 })); // DELETE fails

    renderPage();
    await screen.findByRole("button", { name: /send test message/i });

    await user.click(screen.getByRole("button", { name: "Remove integration" }));
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Remove integration" }));

    expect(
      await screen.findByText("Failed to remove the integration. Try again.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(screen.getByText(/isn't retrievable once removed/i)).toBeInTheDocument(); // modal stays open
  });

  it("confirming removes the integration and resets the form", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(existingIntegration())) // initial load
      .mockResolvedValueOnce(jsonResponse(undefined)) // DELETE
      .mockResolvedValueOnce(jsonResponse(null, { status: 204 })); // refetch after invalidation - none configured

    renderPage();
    await screen.findByRole("button", { name: /send test message/i });

    await user.click(screen.getByRole("button", { name: "Remove integration" }));
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Remove integration" }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/slack-integration", { method: "DELETE" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    // Wait for the invalidateQueries-triggered refetch (the 3rd queued mock) to actually fire
    // before the test ends and RTL unmounts the tree - otherwise that fetch promise is still
    // in-flight at unmount, and its resolution can race past cleanup into whatever test runs
    // next in this file. That's exactly the kind of order-dependent flakiness that was making
    // the "unsaved changes warning" tests below fail intermittently only under a full-suite run.
    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(3));
  });
});

describe("AdminSlackPage - unsaved changes warning", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function dispatchBeforeUnload(): BeforeUnloadEvent {
    const event = new Event("beforeunload", { cancelable: true }) as BeforeUnloadEvent;
    window.dispatchEvent(event);
    return event;
  }

  it("does not warn on load, before anything is typed", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(existingIntegration()));

    renderPage();
    await screen.findByRole("button", { name: /send test message/i });

    expect(dispatchBeforeUnload().defaultPrevented).toBe(false);
  });

  it("warns once a fresh webhook URL is typed - the one thing here that isn't retrievable if lost", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, status: 204, json: async () => null, text: async () => "" } as Response);

    renderPage();
    const urlInput = await screen.findByPlaceholderText(/hooks\.slack\.com/i);

    expect(dispatchBeforeUnload().defaultPrevented).toBe(false); // empty field - nothing to lose yet

    await user.type(urlInput, "https://hooks.slack.com/services/T1/B1/x");

    expect(dispatchBeforeUnload().defaultPrevented).toBe(true);
    expect(screen.getByText("Unsaved changes.")).toBeInTheDocument();
  });

  it("warns when a checkbox is toggled away from the loaded config", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(existingIntegration({ enabled: true })));

    renderPage();
    await screen.findByRole("button", { name: /send test message/i });
    expect(dispatchBeforeUnload().defaultPrevented).toBe(false);

    await user.click(screen.getByLabelText("Enabled"));

    expect(dispatchBeforeUnload().defaultPrevented).toBe(true);
  });

  it("does not warn once the typed webhook is saved", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce({ ok: true, status: 204, json: async () => null, text: async () => "" } as Response) // initial load
      .mockResolvedValueOnce(jsonResponse(existingIntegration())) // save
      .mockResolvedValueOnce(jsonResponse(existingIntegration())); // refetch after invalidation

    renderPage();
    const urlInput = await screen.findByPlaceholderText(/hooks\.slack\.com/i);
    await user.type(urlInput, "https://hooks.slack.com/services/T1/B1/x");
    expect(dispatchBeforeUnload().defaultPrevented).toBe(true);

    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(dispatchBeforeUnload().defaultPrevented).toBe(false));
  });
});
