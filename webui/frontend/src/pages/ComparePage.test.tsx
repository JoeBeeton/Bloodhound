import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useSearchParams } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { ComparePage } from "./ComparePage";

vi.mock("../lib/apiClient", async () => {
  const actual = await vi.importActual<typeof import("../lib/apiClient")>("../lib/apiClient");
  return { ...actual, apiFetch: vi.fn() };
});
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
// Recharts' ResponsiveContainer needs a real layout/ResizeObserver jsdom doesn't provide - these
// tests are about ComparePage's own URL-persisted selection state, not the chart's rendering, so
// stub it out the same way Shell/AdminSubNav get stubbed elsewhere in this suite.
vi.mock("../components/CompareTrendChart", () => ({
  CompareTrendChart: ({ series, mode }: { series: unknown[]; mode: string }) => (
    <div data-testid="chart" data-mode={mode}>
      {series.length} series
    </div>
  ),
}));

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function target(id: string, hostname: string, targetType: "OWN" | "COMPETITOR" = "OWN") {
  return { id, hostname, targetType, ownershipStatus: "UNAUTHORIZED", scanCadenceSeconds: 3600, isActive: true, notes: null };
}

let capturedUrl = "";

function renderAt(path: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/compare"
            element={
              <>
                <ComparePage />
                <UrlSpy />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// MemoryRouter's history is in-memory, not window.location - so observing the current URL means
// reading useSearchParams itself from a sibling element, rather than window.location.search.
function UrlSpy() {
  const [params] = useSearchParams();
  capturedUrl = params.toString();
  return null;
}

const mockedApiFetch = vi.mocked(apiFetch);

describe("ComparePage URL-persisted selection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    capturedUrl = "";
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("defaults to selecting OWN targets when the URL has no targetIds param", async () => {
    mockedApiFetch.mockImplementation(async (url) => {
      if (url.toString().includes("/compare")) return jsonResponse([]);
      return jsonResponse([target("t1", "own.example.com", "OWN"), target("t2", "rival.example.com", "COMPETITOR")]);
    });

    renderAt("/compare");

    await screen.findByText("own.example.com");
    await waitFor(() => expect(screen.getByRole("button", { name: /own\.example\.com/ })).toHaveAttribute("aria-pressed", "true"));
    expect(screen.getByRole("button", { name: /rival\.example\.com/ })).toHaveAttribute("aria-pressed", "false");
  });

  it("an explicit targetIds param in the URL overrides the OWN-targets default", async () => {
    mockedApiFetch.mockImplementation(async (url) => {
      if (url.toString().includes("/compare")) return jsonResponse([]);
      return jsonResponse([target("t1", "own.example.com", "OWN"), target("t2", "rival.example.com", "COMPETITOR")]);
    });

    renderAt("/compare?targetIds=t2");

    await screen.findByText("rival.example.com");
    await waitFor(() => expect(screen.getByRole("button", { name: /rival\.example\.com/ })).toHaveAttribute("aria-pressed", "true"));
    expect(screen.getByRole("button", { name: /own\.example\.com/ })).toHaveAttribute("aria-pressed", "false");
  });

  it("toggling a target writes the new selection into the URL, so a reload reproduces it", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockImplementation(async (url) => {
      if (url.toString().includes("/compare")) return jsonResponse([]);
      return jsonResponse([target("t1", "own.example.com", "OWN"), target("t2", "rival.example.com", "COMPETITOR")]);
    });

    renderAt("/compare");
    await screen.findByText("rival.example.com");

    await user.click(screen.getByRole("button", { name: /rival\.example\.com/ }));

    await waitFor(() => expect(capturedUrl).toContain("targetIds=t1%2Ct2"));
  });

  it("switching to Full picture mode persists mode=full in the URL", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockImplementation(async (url) => {
      if (url.toString().includes("/compare")) return jsonResponse([]);
      return jsonResponse([target("t1", "own.example.com", "OWN")]);
    });

    renderAt("/compare");
    await screen.findByText("own.example.com");

    await user.click(screen.getByRole("button", { name: "Full picture" }));

    await waitFor(() => expect(capturedUrl).toContain("mode=full"));
    expect(screen.getByTestId("chart")).toHaveAttribute("data-mode", "full");
  });

  it("Fair comparison is the default and does not add a mode param to the URL", async () => {
    mockedApiFetch.mockImplementation(async (url) => {
      if (url.toString().includes("/compare")) return jsonResponse([]);
      return jsonResponse([target("t1", "own.example.com", "OWN")]);
    });

    renderAt("/compare");
    await screen.findByText("own.example.com");

    expect(screen.getByRole("button", { name: "Fair comparison" })).toHaveAttribute("aria-pressed", "true");
    expect(capturedUrl).not.toContain("mode=");
  });
});
