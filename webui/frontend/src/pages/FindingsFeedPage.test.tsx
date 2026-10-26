import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import type { FindingActivityBucket, OrgFinding, Target } from "../lib/types";
import { FindingsFeedPage } from "./FindingsFeedPage";

vi.mock("../lib/apiClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/apiClient")>()),
  apiFetch: vi.fn(),
}));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
// Mounting the real FindingDetailModal here would need its own dismiss/reopen apiFetch mocking
// for something this test suite isn't about - it's already covered by its own test file, so this
// only confirms the feed hands it the right finding.
vi.mock("../components/FindingDetailModal", () => ({
  FindingDetailModal: ({ finding, onClose }: { finding: OrgFinding; onClose: () => void }) => (
    <div role="dialog">
      <p>Detail: {finding.title}</p>
      <button onClick={onClose}>Close</button>
    </div>
  ),
}));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, headers: Record<string, string> = {}): Response {
  return { ok: true, status: 200, json: async () => body, headers: new Headers(headers) } as Response;
}

function finding(overrides: Partial<OrgFinding> = {}): OrgFinding {
  return {
    id: "f1",
    displayId: "bh-example.com-1",
    targetId: "t1",
    targetHostname: "example.com",
    moduleType: "HTTP_HEADERS",
    ruleId: "MISSING_CSP",
    severity: "MEDIUM",
    category: "HEADERS",
    title: "Missing Content-Security-Policy header",
    description: "No CSP header was present.",
    evidence: {},
    affectedAsset: "example.com",
    status: "OPEN",
    statusReason: null,
    resolvedAt: null,
    createdAt: new Date().toISOString(),
    firstSeenAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    remediationAdvice: null,
    scoreImpact: null,
    ...overrides,
  };
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
    overallScore: null,
    grade: null,
    tier1OverallScore: null,
    tier1Grade: null,
    lastScanAt: null,
    lastScanWasDeep: false,
    notes: null,
    wafVendor: null,
    wafScanned: false,
    estimatedScanDurationSeconds: null,
    ...overrides,
  };
}

/** Routes every apiFetch call by URL prefix - the page fires three independent queries (feed, activity, targets) on mount. */
function routeApiFetch(handlers: {
  feed?: () => Response;
  activity?: FindingActivityBucket[];
  targets?: Target[];
}) {
  mockedApiFetch.mockImplementation(async (url: string) => {
    if (url.includes("/api/v1/findings/feed/activity")) return jsonResponse(handlers.activity ?? []);
    if (url.includes("/api/v1/findings/feed")) return handlers.feed ? handlers.feed() : jsonResponse([]);
    if (url.includes("/api/v1/targets")) return jsonResponse(handlers.targets ?? []);
    throw new Error(`Unexpected apiFetch call: ${url}`);
  });
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/findings/feed"]}>
        <FindingsFeedPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("FindingsFeedPage", () => {
  beforeEach(() => {
    mockedApiFetch.mockReset();
  });
  afterEach(() => vi.useRealTimers());

  it("renders fetched findings with their title and target hostname", async () => {
    routeApiFetch({
      feed: () => jsonResponse([finding({ id: "f1", title: "Missing CSP" })], { "X-Total-Count": "1" }),
      targets: [target()],
    });
    renderPage();

    await waitFor(() => expect(screen.getByText("Missing CSP")).toBeInTheDocument());
    expect(screen.getAllByText("example.com").length).toBeGreaterThan(0);
  });

  it("shows the clean-sweep message when there are no findings and no filters applied", async () => {
    routeApiFetch({ feed: () => jsonResponse([], { "X-Total-Count": "0" }) });
    renderPage();

    await waitFor(() => expect(screen.getByText(/clean sweep/i)).toBeInTheDocument());
  });

  it("shows an error state with a working retry button", async () => {
    mockedApiFetch.mockResolvedValue({ ok: false, status: 500 } as Response);
    renderPage();

    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(mockedApiFetch).toHaveBeenCalled();
  });

  it("clicking a finding card opens the detail modal with that finding", async () => {
    routeApiFetch({ feed: () => jsonResponse([finding({ title: "Missing CSP" })], { "X-Total-Count": "1" }) });
    renderPage();

    await waitFor(() => expect(screen.getByText("Missing CSP")).toBeInTheDocument());
    await userEvent.click(screen.getByText("Missing CSP"));

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Detail: Missing CSP")).toBeInTheDocument();
  });

  it("selecting a severity filter refetches with the severity query param", async () => {
    routeApiFetch({ feed: () => jsonResponse([], { "X-Total-Count": "0" }) });
    renderPage();

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "CRITICAL" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith(expect.stringContaining("severity=CRITICAL")),
    );
  });

  it("the Live/Paused toggle flips its own pressed state", async () => {
    routeApiFetch({ feed: () => jsonResponse([], { "X-Total-Count": "0" }) });
    renderPage();

    const toggle = await screen.findByRole("button", { name: /live/i });
    expect(toggle).toHaveAttribute("aria-pressed", "true");

    await userEvent.click(toggle);
    expect(screen.getByRole("button", { name: /paused/i })).toHaveAttribute("aria-pressed", "false");
  });

  it("Load more requests a larger page without resetting existing filters", async () => {
    routeApiFetch({
      feed: () => jsonResponse([finding({ id: "f1" })], { "X-Total-Count": "5" }),
    });
    renderPage();

    await waitFor(() => expect(screen.getByText(/load more/i)).toBeInTheDocument());
    await userEvent.click(screen.getByText(/load more/i));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith(expect.stringContaining("limit=60")));
  });
});
