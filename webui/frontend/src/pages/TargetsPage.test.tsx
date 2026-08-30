import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { TargetsPage } from "./TargetsPage";
import type { Target } from "../lib/types";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
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
