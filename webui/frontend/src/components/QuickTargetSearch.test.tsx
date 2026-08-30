import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { QuickTargetSearch } from "./QuickTargetSearch";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));

const navigateSpy = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateSpy };
});

const mockedApiFetch = vi.mocked(apiFetch);

function target(overrides: Record<string, unknown> = {}) {
  return {
    id: "t1",
    hostname: "example.com",
    targetType: "OWN",
    authorizationStatus: "AUTHORIZED",
    scanCadenceSeconds: 86400,
    nextScanAt: "2026-01-02T00:00:00Z",
    isActive: true,
    createdAt: "2026-01-01T00:00:00Z",
    overallScore: 92,
    grade: "A",
    ...overrides,
  };
}

function renderComponent() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <QuickTargetSearch />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("QuickTargetSearch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not fetch targets until the panel is opened", () => {
    renderComponent();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  it("opens on Ctrl+K from anywhere on the page and fetches the full target list", async () => {
    mockedApiFetch.mockResolvedValueOnce({ ok: true, json: async () => [target()] } as Response);

    renderComponent();
    await userEvent.keyboard("{Control>}k{/Control}");

    expect(await screen.findByRole("option", { name: /example\.com/i })).toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/targets?includeInactive=true");
  });

  it("opens when the trigger button is clicked", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, json: async () => [target()] } as Response);

    renderComponent();
    await user.click(screen.getByRole("button", { name: /search targets/i }));

    expect(await screen.findByRole("option", { name: /example\.com/i })).toBeInTheDocument();
  });

  it("filters results by hostname substring as the user types", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [target({ id: "t1", hostname: "alpha.example.com" }), target({ id: "t2", hostname: "beta.example.com" })],
    } as Response);

    renderComponent();
    await user.click(screen.getByRole("button", { name: /search targets/i }));
    await screen.findByRole("option", { name: /alpha\.example\.com/i });

    await user.type(screen.getByLabelText(/search targets by hostname/i), "alpha");

    expect(screen.getByRole("option", { name: /alpha\.example\.com/i })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /beta\.example\.com/i })).not.toBeInTheDocument();
  });

  it("shows a removed target dimly, and navigating to it still works", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [target({ id: "t1", hostname: "gone.example.com", isActive: false })],
    } as Response);

    renderComponent();
    await user.click(screen.getByRole("button", { name: /search targets/i }));
    const option = await screen.findByRole("option", { name: /gone\.example\.com/i });
    expect(option.textContent).toMatch(/removed/i);

    await user.click(option);
    expect(navigateSpy).toHaveBeenCalledWith("/targets/t1");
  });

  it("pressing Enter navigates to the highlighted result and closes the panel", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, json: async () => [target({ id: "t1", hostname: "example.com" })] } as Response);

    renderComponent();
    await user.click(screen.getByRole("button", { name: /search targets/i }));
    await screen.findByRole("option", { name: /example\.com/i });

    await user.keyboard("{Enter}");

    expect(navigateSpy).toHaveBeenCalledWith("/targets/t1");
    await waitFor(() => expect(screen.queryByRole("listbox")).not.toBeInTheDocument());
  });

  it("pressing Escape closes the panel without navigating", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, json: async () => [target()] } as Response);

    renderComponent();
    await user.click(screen.getByRole("button", { name: /search targets/i }));
    await screen.findByRole("option", { name: /example\.com/i });

    await user.keyboard("{Escape}");

    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  it("shows a no-match message when nothing matches the typed substring", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, json: async () => [target()] } as Response);

    renderComponent();
    await user.click(screen.getByRole("button", { name: /search targets/i }));
    await screen.findByRole("option", { name: /example\.com/i });

    await user.type(screen.getByLabelText(/search targets by hostname/i), "zzz-nonexistent");

    expect(await screen.findByText(/no targets match/i)).toBeInTheDocument();
  });
});
