import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { AdminAuditLogPage } from "./AdminAuditLogPage";

vi.mock("../lib/apiClient", async () => {
  const actual = await vi.importActual<typeof import("../lib/apiClient")>("../lib/apiClient");
  return { ...actual, apiFetch: vi.fn() };
});
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/AdminSubNav", () => ({ AdminSubNav: () => <div /> }));
vi.mock("../lib/useAuth", () => ({
  useAuth: () => ({ status: "authenticated", user: { organizationId: "org-1", role: "ADMIN" } }),
}));

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number; totalCount?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    headers: new Headers(init.totalCount !== undefined ? { "X-Total-Count": String(init.totalCount) } : {}),
    json: async () => body,
  } as Response;
}

function entry(overrides: Record<string, unknown> = {}) {
  return {
    id: "e1",
    actorUserId: "u1",
    actorEmail: "alice@example.com",
    action: "TARGET_DELETED",
    targetType: "TARGET",
    targetId: "t1",
    detail: "hostname=example.com",
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AdminAuditLogPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const mockedApiFetch = vi.mocked(apiFetch);

describe("AdminAuditLogPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("loads without any filter params on first render", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 }));

    renderPage();

    await screen.findByText("alice@example.com", {}, { timeout: 5000 });
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/audit-log?limit=50&offset=0");
  });

  it("debounces the actor-email search and refetches with the actorEmail param", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 })) // initial load
      .mockResolvedValueOnce(jsonResponse([entry({ actorEmail: "bob@example.com" })], { totalCount: 1 })); // after search

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    await user.type(screen.getByPlaceholderText(/filter by actor email/i), "bob");

    await waitFor(
      () =>
        expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/audit-log?limit=50&offset=0&actorEmail=bob"),
      { timeout: 5000 },
    );
    expect(await screen.findByText("bob@example.com", {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("clicking an action chip filters by that action and toggling it again clears it", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 })) // initial load
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 })) // filtered by action
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 })); // toggled back off

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    const chip = screen.getByRole("button", { name: "Target deleted" });
    expect(chip).toHaveAttribute("aria-pressed", "false");

    await user.click(chip);
    await waitFor(
      () =>
        expect(mockedApiFetch).toHaveBeenCalledWith(
          "/api/v1/orgs/org-1/audit-log?limit=50&offset=0&action=TARGET_DELETED",
        ),
      { timeout: 5000 },
    );
    expect(chip).toHaveAttribute("aria-pressed", "true");

    await user.click(chip);
    await waitFor(() => expect(chip).toHaveAttribute("aria-pressed", "false"));
    expect(mockedApiFetch).toHaveBeenLastCalledWith("/api/v1/orgs/org-1/audit-log?limit=50&offset=0");
  });

  it("shows 'Clear filters' only once a filter is active, and clearing resets both", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 }))
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 }))
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 }));

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });
    expect(screen.queryByText("Clear filters ✕")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Target deleted" }));
    await waitFor(() => expect(screen.getByText("Clear filters ✕")).toBeInTheDocument());

    await user.click(screen.getByText("Clear filters ✕"));
    await waitFor(() => expect(screen.queryByText("Clear filters ✕")).not.toBeInTheDocument());
    expect(mockedApiFetch).toHaveBeenLastCalledWith("/api/v1/orgs/org-1/audit-log?limit=50&offset=0");
  });

  it("shows the filtered empty state distinctly from the no-history-at-all empty state", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 }))
      .mockResolvedValueOnce(jsonResponse([], { totalCount: 0 }));

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Rule enabled" }));

    expect(
      await screen.findByText("No audited actions match the selected filters.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
  });

  it("hides the Export CSV button when there is no history yet", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([], { totalCount: 0 }));

    renderPage();
    await screen.findByText("No audited actions yet.", {}, { timeout: 5000 });

    expect(screen.queryByRole("button", { name: /export csv/i })).not.toBeInTheDocument();
  });

  it("exporting fetches the export endpoint with the current filters and triggers a download", async () => {
    const user = userEvent.setup();
    const clickSpy = vi.fn();
    const originalCreateElement = document.createElement.bind(document);
    vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
      const el = originalCreateElement(tag);
      if (tag === "a") el.click = clickSpy;
      return el;
    });
    URL.createObjectURL = vi.fn(() => "blob:audit-log");
    URL.revokeObjectURL = vi.fn();

    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 })) // initial load
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 })) // filtered by action
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ "Content-Disposition": 'attachment; filename="bloodhound-audit-log-2026-01-01.csv"' }),
        blob: async () => new Blob(["When,Actor,Action,Target Type,Target ID,Detail\r\n"], { type: "text/csv" }),
      } as unknown as Response); // export

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Target deleted" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Target deleted" })).toHaveAttribute("aria-pressed", "true"));

    await user.click(screen.getByRole("button", { name: /export csv/i }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenLastCalledWith(
        "/api/v1/orgs/org-1/audit-log/export?action=TARGET_DELETED",
      ),
    );
    await waitFor(() => expect(clickSpy).toHaveBeenCalledTimes(1));
    expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:audit-log");
  });

  it("shows an error message when the export request fails, without breaking the page", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([entry()], { totalCount: 1 })) // initial load
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 })); // export failure

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: /export csv/i }));

    expect(
      await screen.findByText("Failed to export the audit log. Try again.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
  });

  // A review found these 4 actions - each added by a real backend feature shipped earlier this
  // session (finding dismiss/reopen, bulk target creation, the Active Sessions page) - were never
  // added to ACTION_LABELS: an existing row rendered the raw enum string instead of a label, and
  // (the real user-facing gap, since ACTION_VALUES is derived from that same map) couldn't be
  // filtered for via the action chips at all.
  it.each([
    ["FINDING_DISMISSED", "Finding dismissed"],
    ["FINDING_REOPENED", "Finding reopened"],
    ["TARGETS_BULK_CREATED", "Targets bulk-created"],
    ["USER_SESSION_REVOKED", "Session revoked"],
  ])("renders a real label for %s, and offers it as a filter chip", async (action, label) => {
    // The label text alone isn't a unique query - every known action renders as a filter chip
    // <button> regardless of what's in the loaded page (see ACTION_VALUES.map(...) above), so a
    // matching log row means a second, non-button element with the same text.
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([entry({ action })], { totalCount: 1 }));

    renderPage();
    await screen.findByText("alice@example.com", {}, { timeout: 5000 });

    const matches = screen.getAllByText(label);
    expect(matches.some((el) => el.tagName !== "BUTTON")).toBe(true); // the actual log row
    expect(screen.queryByText(action)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: label })).toBeInTheDocument(); // the filter chip
  });

  it("treats USER_SESSION_REVOKED as a destructive action, styled the same as an existing one like API_KEY_REVOKED", async () => {
    // "Session revoked"/"API key revoked" each appear twice (once as a filter chip <button>, once
    // as the log row's own <span>) - the label alone isn't a unique query, so this picks the
    // non-button match (the actual log row) out of each pair rather than asserting on whichever
    // element happens to be found first.
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse(
        [
          entry({ id: "e1", action: "USER_SESSION_REVOKED", actorEmail: "alice@example.com" }),
          entry({ id: "e2", action: "API_KEY_REVOKED", actorEmail: "bob@example.com" }),
        ],
        { totalCount: 2 },
      ),
    );

    renderPage();
    await screen.findByText("bob@example.com", {}, { timeout: 5000 });

    const revokedRow = screen.getAllByText("Session revoked").find((el) => el.tagName !== "BUTTON");
    const apiKeyRevokedRow = screen.getAllByText("API key revoked").find((el) => el.tagName !== "BUTTON");
    expect(revokedRow).toBeDefined();
    expect(revokedRow!.className).toBe(apiKeyRevokedRow!.className);
  });
});
