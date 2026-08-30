import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { ScanDetailPage } from "./ScanDetailPage";

vi.mock("../lib/apiClient", async () => {
  const actual = await vi.importActual<typeof import("../lib/apiClient")>("../lib/apiClient");
  return { ...actual, apiFetch: vi.fn() };
});
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, headers: new Headers(), json: async () => body } as Response;
}

function run(overrides: Record<string, unknown> = {}) {
  return {
    id: "run-1",
    targetId: "t1",
    targetHostname: "example.com",
    triggeredBy: "MANUAL",
    startedAt: "2026-01-01T00:00:00Z",
    completedAt: null,
    status: "RUNNING",
    jobs: [
      {
        id: "job-1",
        moduleType: "HTTP_HEADERS",
        status: "RUNNING",
        attemptCount: 1,
        maxAttempts: 3,
        errorDetail: null,
        attempts: [],
        host: null,
      },
    ],
    ...overrides,
  };
}

function renderAt(path: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/scans/:id" element={<ScanDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const mockedApiFetch = vi.mocked(apiFetch);

function mockRoutes(runBody: ReturnType<typeof run>, cancelResult?: { ok: boolean; status?: number; body?: unknown }) {
  mockedApiFetch.mockImplementation(async (url) => {
    const href = url.toString();
    if (href.includes("/cancel")) {
      if (!cancelResult || !cancelResult.ok) {
        return jsonResponse(null, { ok: false, status: cancelResult?.status ?? 500 });
      }
      return jsonResponse(cancelResult.body ?? { ...runBody, status: "CANCELLED" });
    }
    if (href.includes("/findings")) return jsonResponse([]);
    return jsonResponse(runBody);
  });
}

describe("ScanDetailPage cancel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the Cancel scan button while the run is RUNNING", async () => {
    mockRoutes(run({ status: "RUNNING" }));

    renderAt("/scans/run-1");

    await screen.findByText("example.com");
    expect(screen.getByRole("button", { name: "Cancel scan" })).toBeInTheDocument();
  });

  it("hides the Cancel scan button once the run is no longer RUNNING", async () => {
    mockRoutes(run({ status: "COMPLETE", completedAt: "2026-01-01T00:05:00Z" }));

    renderAt("/scans/run-1");

    await screen.findByText("example.com");
    expect(screen.queryByRole("button", { name: "Cancel scan" })).not.toBeInTheDocument();
  });

  it("clicking Cancel scan opens a confirmation modal that does not fire the request by itself", async () => {
    const user = userEvent.setup();
    mockRoutes(run());

    renderAt("/scans/run-1");
    await screen.findByText("example.com");

    await user.click(screen.getByRole("button", { name: "Cancel scan" }));

    expect(screen.getByRole("dialog", { name: "Cancel scan" })).toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalledWith(expect.stringContaining("/cancel"), expect.anything());
  });

  it("confirming cancels the run and the page reflects CANCELLED status", async () => {
    const user = userEvent.setup();
    mockRoutes(run(), { ok: true });

    renderAt("/scans/run-1");
    await screen.findByText("example.com");

    await user.click(screen.getByRole("button", { name: "Cancel scan" }));
    const dialog = screen.getByRole("dialog", { name: "Cancel scan" });
    await user.click(within(dialog).getByRole("button", { name: "Cancel scan" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/runs/run-1/cancel", { method: "POST" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(screen.getByText("CANCELLED")).toBeInTheDocument();
    // Once cancelled it's terminal - the button that reopens the confirmation must not reappear.
    expect(screen.queryByRole("button", { name: "Cancel scan" })).not.toBeInTheDocument();
  });

  it("shows an error inside the modal and stays open if the scan already finished (409)", async () => {
    const user = userEvent.setup();
    mockRoutes(run(), { ok: false, status: 409 });

    renderAt("/scans/run-1");
    await screen.findByText("example.com");

    await user.click(screen.getByRole("button", { name: "Cancel scan" }));
    const dialog = screen.getByRole("dialog", { name: "Cancel scan" });
    await user.click(within(dialog).getByRole("button", { name: "Cancel scan" }));

    expect(await screen.findByText("This scan already finished.")).toBeInTheDocument();
    expect(screen.getByRole("dialog", { name: "Cancel scan" })).toBeInTheDocument();
  });

  it("Keep running closes the modal without cancelling", async () => {
    const user = userEvent.setup();
    mockRoutes(run());

    renderAt("/scans/run-1");
    await screen.findByText("example.com");

    await user.click(screen.getByRole("button", { name: "Cancel scan" }));
    await user.click(screen.getByRole("button", { name: "Keep running" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalledWith(expect.stringContaining("/cancel"), expect.anything());
  });
});
