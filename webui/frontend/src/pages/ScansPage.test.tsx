import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { scanHasFailure, ScansPage } from "./ScansPage";
import type { ActiveScan } from "../lib/types";

vi.mock("../lib/apiClient", async () => {
  const actual = await vi.importActual<typeof import("../lib/apiClient")>("../lib/apiClient");
  return { ...actual, apiFetch: vi.fn() };
});
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/WorkerPanel", () => ({ WorkerPanel: () => <div /> }));

function scan(modules: Array<{ moduleType: string; status: string; host?: string | null }>): ActiveScan {
  return {
    id: "scan-1",
    targetId: "target-1",
    targetHostname: "example.com",
    triggeredBy: "manual",
    startedAt: new Date().toISOString(),
    completedJobs: 0,
    totalJobs: modules.length,
    etaSeconds: 30,
    modules: modules.map((m) => ({ moduleType: m.moduleType, status: m.status, host: m.host ?? null })),
  };
}

describe("scanHasFailure", () => {
  it("is false when every module is still running or complete", () => {
    expect(
      scanHasFailure(
        scan([
          { moduleType: "DNS", status: "COMPLETE" },
          { moduleType: "TLS", status: "RUNNING" },
        ]),
      ),
    ).toBe(false);
  });

  it("is true when any module has failed, regardless of the others' status", () => {
    expect(
      scanHasFailure(
        scan([
          { moduleType: "DNS", status: "COMPLETE" },
          { moduleType: "TLS", status: "FAILED" },
          { moduleType: "HEADERS", status: "RUNNING" },
        ]),
      ),
    ).toBe(true);
  });

  it("is false for a scan with no modules yet", () => {
    expect(scanHasFailure(scan([]))).toBe(false);
  });
});

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number; totalCount?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    headers: new Headers(init.totalCount !== undefined ? { "X-Total-Count": String(init.totalCount) } : {}),
    json: async () => body,
  } as Response;
}

function recentScan(overrides: Record<string, unknown> = {}) {
  return {
    id: "r1",
    targetId: "t1",
    targetHostname: "example.com",
    triggeredBy: "MANUAL",
    status: "FAILED",
    startedAt: "2026-01-01T00:00:00Z",
    completedAt: "2026-01-01T00:05:00Z",
    ...overrides,
  };
}

function renderScansPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ScansPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ScansPage - Recent Scans filtering and pagination", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * Routes by URL rather than call order - ScansPage's own active-scans query and
   * RecentScansSection's recent-scans query are two independent useQuery hooks in different
   * components, and React fires child effects before parent effects, so which one's queryFn
   * actually calls apiFetch first is not guaranteed to match render/mount order.
   */
  function mockRecentScans(handler: (url: string) => Response) {
    mockedApiFetch.mockImplementation(async (url: string) => {
      if (url.startsWith("/api/v1/scans/active")) return jsonResponse([]);
      return handler(url);
    });
  }

  it("loads recent scans unfiltered on first render", async () => {
    mockRecentScans(() => jsonResponse([recentScan()], { totalCount: 1 }));

    renderScansPage();

    await screen.findByText("example.com", {}, { timeout: 5000 });
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/scans/recent?limit=30&offset=0");
  });

  it("clicking a status chip filters recent scans by that status", async () => {
    const user = userEvent.setup();
    mockRecentScans((url) =>
      url.includes("status=FAILED")
        ? jsonResponse([recentScan()], { totalCount: 1 })
        : jsonResponse([recentScan()], { totalCount: 1 }),
    );

    renderScansPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    const chip = screen.getByRole("button", { name: "FAILED" });
    expect(chip).toHaveAttribute("aria-pressed", "false");

    await user.click(chip);

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/scans/recent?limit=30&offset=0&status=FAILED"),
    );
    expect(chip).toHaveAttribute("aria-pressed", "true");
  });

  it("clicking an active chip again clears the filter", async () => {
    const user = userEvent.setup();
    mockRecentScans(() => jsonResponse([recentScan()], { totalCount: 1 }));

    renderScansPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    const chip = screen.getByRole("button", { name: "FAILED" });
    await user.click(chip);
    await waitFor(() => expect(chip).toHaveAttribute("aria-pressed", "true"));

    await user.click(chip);
    await waitFor(() => expect(chip).toHaveAttribute("aria-pressed", "false"));
    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/scans/recent?limit=30&offset=0"),
    );
  });

  it("shows 'Load more' only when more results exist, and clicking it fetches a bigger page", async () => {
    const user = userEvent.setup();
    mockRecentScans((url) =>
      url.includes("limit=60")
        ? jsonResponse([recentScan(), recentScan({ id: "r2", targetHostname: "b.example.com" })], { totalCount: 45 })
        : jsonResponse([recentScan()], { totalCount: 45 }),
    );

    renderScansPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    const loadMore = screen.getByRole("button", { name: /load more/i });
    expect(loadMore).toHaveTextContent("44 more");

    await user.click(loadMore);

    expect(await screen.findByText("b.example.com", {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("shows a status-specific empty state when a filter matches nothing", async () => {
    const user = userEvent.setup();
    mockRecentScans((url) =>
      url.includes("status=CANCELLED") ? jsonResponse([], { totalCount: 0 }) : jsonResponse([recentScan()], { totalCount: 1 }),
    );

    renderScansPage();
    await screen.findByText("example.com", {}, { timeout: 5000 });

    await user.click(screen.getByRole("button", { name: "CANCELLED" }));

    expect(await screen.findByText(/no cancelled scans found/i, {}, { timeout: 5000 })).toBeInTheDocument();
  });
});
