import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { TargetsPage } from "./TargetsPage";
import type { Target } from "../lib/types";

vi.mock("../lib/apiClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/apiClient")>()),
  apiFetch: vi.fn(),
}));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../lib/useAuth", () => ({ useAuth: () => ({ user: { role: "ADMIN" } }) }));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function target(overrides: Partial<Target> = {}): Target {
  return {
    id: "t1",
    hostname: "example.com",
    targetType: "OWN",
    authorizationStatus: "AUTHORIZED",
    scanCadenceSeconds: 86400,
    nextScanAt: "2026-01-02T00:00:00Z",
    isActive: true,
    createdAt: "2026-01-01T00:00:00Z",
    overallScore: 85,
    grade: "A",
    tier1OverallScore: 85,
    tier1Grade: "A",
    lastScanAt: "2026-01-01T00:00:00Z",
    lastScanWasDeep: false,
    notes: null,
    wafVendor: null,
    wafScanned: false,
    estimatedScanDurationSeconds: null,
    estimatedTier2ScanDurationSeconds: null,
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <TargetsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("TargetsPage - bulk scan selection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not show the selection toolbar with only one target", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([target()]));

    renderPage();

    await screen.findByText("example.com", {}, { timeout: 5000 });
    expect(screen.queryByLabelText(/select all visible targets/i)).not.toBeInTheDocument();
  });

  it("selecting individual targets updates the count and reveals the bulk-scan button", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })]),
    );

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByLabelText("Select example.com"));

    expect(screen.getByText("1 selected")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scan 1 selected" })).toBeInTheDocument();
  });

  it("'Select all' selects every visible active target, and toggling it again clears them", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })]),
    );

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    const selectAll = screen.getByLabelText(/select all visible targets/i);
    await user.click(selectAll);

    expect(screen.getByText("2 selected")).toBeInTheDocument();
    expect(screen.getByLabelText("Select example.com")).toBeChecked();
    expect(screen.getByLabelText("Select second.example.com")).toBeChecked();

    await user.click(selectAll);
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
  });

  it("clicking 'Scan N selected' fires a scan request per selected target and reports the summary", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })])) // list
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse({ id: "run-1" })) // scan t1
      .mockResolvedValueOnce(jsonResponse({ id: "run-2" })); // scan t2

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByLabelText(/select all visible targets/i));
    await user.click(screen.getByRole("button", { name: "Scan 2 selected" }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/targets/t1/scan", { method: "POST" }));
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/targets/t2/scan", { method: "POST" });

    expect(await screen.findByText(/started 2 scans/i, {}, { timeout: 5000 })).toBeInTheDocument();
    // Selection clears once the bulk action completes.
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
  });

  it("reports a partial-failure summary when one of several scan requests fails", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })]))
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse({ id: "run-1" }))
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByLabelText(/select all visible targets/i));
    await user.click(screen.getByRole("button", { name: "Scan 2 selected" }));

    const summary = await screen.findByRole("status", {}, { timeout: 5000 });
    expect(summary.textContent).toMatch(/started 1 scan/i);
    expect(summary.textContent).toMatch(/1 failed to start/i);
  });

  it("hides selection checkboxes in the 'Show removed' view", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })])) // active view
      .mockResolvedValueOnce(jsonResponse([])) // portfolios (cached across the showRemoved toggle - queryKey doesn't depend on it)
      .mockResolvedValueOnce(
        jsonResponse([target({ id: "t3", hostname: "gone.example.com", isActive: false })]),
      ); // removed view

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: /show removed/i }));

    await screen.findByText("gone.example.com", {}, { timeout: 5000 });
    expect(screen.queryByLabelText(/select all visible targets/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Select gone.example.com")).not.toBeInTheDocument();
  });
});

describe("TargetsPage - notes indicator and search", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // The filter input only renders once there are more than 5 targets - pad the list so it shows.
  function manyTargets(overrides: Partial<Target>[]): Target[] {
    const named = overrides.map((o, i) => target({ id: `named-${i}`, hostname: `named-${i}.example.com`, ...o }));
    const padding = Array.from({ length: 5 }, (_, i) =>
      target({ id: `pad-${i}`, hostname: `pad-${i}.example.com` }),
    );
    return [...named, ...padding];
  }

  it("shows a notes indicator only on targets that have notes", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse(manyTargets([{ hostname: "annotated.example.com", notes: "staging environment" }, { hostname: "bare.example.com", notes: null }])),
    );

    renderPage();
    await screen.findByText("annotated.example.com", {}, { timeout: 5000 });

    expect(screen.getByLabelText(/notes: staging environment/i)).toBeInTheDocument();
    expect(screen.getAllByText("📝")).toHaveLength(1);
  });

  it("searching matches a target by its notes content, not just its hostname", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse(
        manyTargets([
          { hostname: "prod-a.example.com", notes: "primary customer-facing domain" },
          { hostname: "prod-b.example.com", notes: "internal admin portal" },
        ]),
      ),
    );

    renderPage();
    await screen.findByText("prod-a.example.com", {}, { timeout: 5000 });

    await user.type(screen.getByPlaceholderText(/filter by hostname or notes/i), "customer-facing");

    expect(screen.getByText("prod-a.example.com")).toBeInTheDocument();
    expect(screen.queryByText("prod-b.example.com")).not.toBeInTheDocument();
    expect(screen.queryByText("pad-0.example.com")).not.toBeInTheDocument();
  });
});

describe("TargetsPage - next scan label", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the next scheduled scan time and a duration estimate for an active target", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse([
        target({
          hostname: "scheduled.example.com",
          nextScanAt: "2026-01-02T00:00:00Z",
          estimatedScanDurationSeconds: 125,
        }),
      ]),
    );

    renderPage();
    await screen.findByText("scheduled.example.com", {}, { timeout: 5000 });

    expect(screen.getByText(/next scan:/i)).toBeInTheDocument();
    expect(screen.getByText(/\(Tier 1, ~2m 5s\)/)).toBeInTheDocument();
  });

  it("shows a separate Tier 2 estimate beside the Deep scan button for an authorized target", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse([
        target({
          hostname: "deep.example.com",
          authorizationStatus: "AUTHORIZED",
          estimatedTier2ScanDurationSeconds: 905,
        }),
      ]),
    );

    renderPage();
    await screen.findByText("deep.example.com", {}, { timeout: 5000 });

    expect(screen.getByText(/Tier 2, ~15m 5s/)).toBeInTheDocument();
  });

  it("omits the Tier 2 estimate for a target that isn't authorized", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse([
        target({
          hostname: "unauthorized.example.com",
          authorizationStatus: "UNAUTHORIZED",
          estimatedTier2ScanDurationSeconds: null,
        }),
      ]),
    );

    renderPage();
    await screen.findByText("unauthorized.example.com", {}, { timeout: 5000 });

    expect(screen.queryByText(/Tier 2,/)).not.toBeInTheDocument();
  });

  it("omits the duration estimate when there isn't enough scan history yet", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse([
        target({
          hostname: "new.example.com",
          nextScanAt: "2026-01-02T00:00:00Z",
          estimatedScanDurationSeconds: null,
        }),
      ]),
    );

    renderPage();
    await screen.findByText("new.example.com", {}, { timeout: 5000 });

    expect(screen.getByText(/next scan:/i)).toBeInTheDocument();
    expect(screen.queryByText(/~/)).not.toBeInTheDocument();
  });

  it("hides the next scan time for a deactivated (removed) target", async () => {
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse([
        target({
          hostname: "removed.example.com",
          isActive: false,
          estimatedScanDurationSeconds: 90,
        }),
      ]),
    );

    renderPage();
    await screen.findByText("removed.example.com", {}, { timeout: 5000 });

    expect(screen.queryByText(/next scan:/i)).not.toBeInTheDocument();
  });
});

describe("TargetsPage - scan-now failure surfacing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows a specific message when a scan is already running (409), not a generic failure", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target()])) // list
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 409 })); // scan attempt

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Scan now" }));

    expect(
      await screen.findByText("A scan is already running for this target.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
  });

  it("shows a generic message for a non-409 scan failure", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target()]))
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Scan now" }));

    expect(await screen.findByText("Failed to start scan.", {}, { timeout: 5000 })).toBeInTheDocument();
  });
});

describe("TargetsPage - bulk remove", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("clicking 'Remove N selected' opens one shared confirmation listing every selected hostname, without removing anything yet", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })]))
      .mockResolvedValueOnce(jsonResponse([])); // portfolios

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByLabelText(/select all visible targets/i));
    await user.click(screen.getByRole("button", { name: "Remove 2 selected" }));

    const dialog = screen.getByRole("dialog");
    expect(screen.getByRole("heading", { name: "Remove targets" })).toBeInTheDocument();
    expect(within(dialog).getByText("example.com")).toBeInTheDocument();
    expect(within(dialog).getByText("second.example.com")).toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(2); // list + portfolios - no PATCH yet
  });

  it("Cancel closes the confirmation without removing anything", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })]))
      .mockResolvedValueOnce(jsonResponse([])); // portfolios

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByLabelText(/select all visible targets/i));
    await user.click(screen.getByRole("button", { name: "Remove 2 selected" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("heading", { name: "Remove targets" })).not.toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledTimes(2); // list + portfolios
  });

  it("confirming fires one PATCH per selected target and reports the summary", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })])) // list
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse({ ...target(), isActive: false })) // PATCH t1
      .mockResolvedValueOnce(jsonResponse({ ...target({ id: "t2" }), isActive: false })); // PATCH t2

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByLabelText(/select all visible targets/i));
    await user.click(screen.getByRole("button", { name: "Remove 2 selected" }));
    await user.click(screen.getByRole("button", { name: "Remove 2" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/targets/t1", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ isActive: false }),
      }),
    );
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/targets/t2", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ isActive: false }),
    });

    expect(await screen.findByText(/removed 2 targets/i, {}, { timeout: 5000 })).toBeInTheDocument();
    // Modal closes and selection clears once the bulk action completes.
    expect(screen.queryByRole("heading", { name: "Remove targets" })).not.toBeInTheDocument();
    expect(screen.queryByText(/selected/)).not.toBeInTheDocument();
  });

  it("reports a partial-failure summary when one of several removals fails", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target(), target({ id: "t2", hostname: "second.example.com" })]))
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse({ ...target(), isActive: false }))
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByLabelText(/select all visible targets/i));
    await user.click(screen.getByRole("button", { name: "Remove 2 selected" }));
    await user.click(screen.getByRole("button", { name: "Remove 2" }));

    const summary = await screen.findByRole("status", {}, { timeout: 5000 });
    expect(summary.textContent).toMatch(/removed 1 target/i);
    expect(summary.textContent).toMatch(/1 failed/i);
  });
});

describe("TargetsPage - bulk add targets", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("toggling 'Bulk add multiple' swaps the hostname input for a multi-line textarea", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse([]));

    renderPage();
    await screen.findByLabelText("Hostname", {}, { timeout: 5000 });

    expect(screen.getByLabelText("Hostname")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Bulk add multiple →" }));

    expect(screen.queryByLabelText("Hostname")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Hostnames (one per line)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add 0 targets" })).toBeDisabled();
  });

  it("submitting a multi-line batch posts the parsed hostname list and reports a partial-success summary", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([])) // initial list load
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(
        jsonResponse([
          { hostname: "good.example.com", created: true, error: null, target: target({ id: "t1", hostname: "good.example.com" }) },
          { hostname: "dupe.example.com", created: false, error: "already tracked for this organization", target: null },
        ]),
      ) // POST .../targets/bulk
      .mockResolvedValueOnce(jsonResponse([target({ id: "t1", hostname: "good.example.com" })])); // refetch after invalidation

    renderPage();
    await screen.findByLabelText("Hostname", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Bulk add multiple →" }));
    // A blank line (from a trailing newline, or extra spacing between pasted hostnames) is
    // filtered out client-side before it's ever sent - matches the backend's own tolerance for
    // blank lines, but keeps the displayed "Add N targets" count accurate either way.
    await user.type(screen.getByLabelText("Hostnames (one per line)"), "good.example.com\n\ndupe.example.com");
    await user.click(screen.getByRole("button", { name: "Add 2 targets" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenNthCalledWith(3, "/api/v1/targets/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostnames: ["good.example.com", "dupe.example.com"], targetType: "OWN" }),
      }),
    );

    const summary = await screen.findByRole("status", {}, { timeout: 5000 });
    expect(summary.textContent).toMatch(/added 1 of 2 targets/i);
    expect(summary.textContent).toMatch(/dupe\.example\.com: already tracked for this organization/i);
    // The textarea clears once the request completes, regardless of partial failure - the failed
    // hostname is still visible in the summary above, not silently lost.
    expect(screen.getByLabelText("Hostnames (one per line)")).toHaveValue("");
  });

  it("a whole-request failure (e.g. a 500) shows a form error and leaves the textarea untouched", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderPage();
    await screen.findByLabelText("Hostname", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Bulk add multiple →" }));
    await user.type(screen.getByLabelText("Hostnames (one per line)"), "example.com");
    await user.click(screen.getByRole("button", { name: "Add 1 target" }));

    expect(await screen.findByText("Failed to add targets.", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByLabelText("Hostnames (one per line)")).toHaveValue("example.com");
  });

  it("a 429 (TargetBulkCreateRateLimiter) shows a specific wait message using Retry-After, not the generic fallback", async () => {
    const user = userEvent.setup();
    const rateLimited = {
      ok: false,
      status: 429,
      headers: { get: (name: string) => (name === "Retry-After" ? "90" : null) },
      json: async () => null,
    } as unknown as Response;
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(rateLimited);

    renderPage();
    await screen.findByLabelText("Hostname", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Bulk add multiple →" }));
    await user.type(screen.getByLabelText("Hostnames (one per line)"), "example.com");
    await user.click(screen.getByRole("button", { name: "Add 1 target" }));

    expect(await screen.findByText("Too many requests. Try again in 2 minutes.", {}, { timeout: 5000 })).toBeInTheDocument();
  });
});

describe("TargetsPage - single remove/restore failure surfacing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows an error inside the confirmation modal when a single Remove fails", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target()])) // list
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 })); // PATCH fails

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Remove" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Remove" }));

    expect(
      await screen.findByText("Failed to remove target. Try again.", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
  });

  it("shows a page-level error when Restore fails (no modal of its own to show it in)", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([target({ isActive: false })])) // list (removed view)
      .mockResolvedValueOnce(jsonResponse([])) // portfolios
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 })); // PATCH fails

    renderPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "Restore" }));

    const summary = await screen.findByRole("status", {}, { timeout: 5000 });
    expect(summary.textContent).toMatch(/failed to update target/i);
  });
});
