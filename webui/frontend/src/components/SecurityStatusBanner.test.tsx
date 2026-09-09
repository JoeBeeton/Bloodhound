import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import type { SecurityStatus } from "../lib/types";
import { SecurityStatusBanner } from "./SecurityStatusBanner";

vi.mock("../lib/apiClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/apiClient")>()),
  apiFetch: vi.fn(),
}));

let mockRole = "ADMIN";
let mockDismissed = false;
const mockDismissSecurityBanner = vi.fn(() => {
  mockDismissed = true;
});
vi.mock("../lib/useAuth", () => ({
  useAuth: () => ({
    user: { role: mockRole },
    securityBannerDismissed: mockDismissed,
    dismissSecurityBanner: mockDismissSecurityBanner,
  }),
}));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as Response;
}

function status(overrides: Partial<SecurityStatus> = {}): SecurityStatus {
  return { jwtSigningKeyIsPlaceholder: true, workerApiKeyIsPlaceholder: true, ...overrides };
}

function renderBanner() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <SecurityStatusBanner />
    </QueryClientProvider>,
  );
}

describe("SecurityStatusBanner", () => {
  beforeEach(() => {
    mockRole = "ADMIN";
    mockDismissed = false;
    mockDismissSecurityBanner.mockClear();
    mockedApiFetch.mockReset();
  });

  it("shows the warning for an admin when both secrets are still placeholders", async () => {
    mockedApiFetch.mockResolvedValue(jsonResponse(status()));
    renderBanner();

    await waitFor(() => expect(screen.getByText(/placeholder secrets still in use/i)).toBeInTheDocument());
    expect(screen.getByText(/JWT_SIGNING_KEY/)).toBeInTheDocument();
    expect(screen.getByText(/WORKER_API_KEY/)).toBeInTheDocument();
  });

  it("singularizes the warning when only one secret is a placeholder", async () => {
    mockedApiFetch.mockResolvedValue(jsonResponse(status({ workerApiKeyIsPlaceholder: false })));
    renderBanner();

    await waitFor(() => expect(screen.getByText(/placeholder secret still in use/i)).toBeInTheDocument());
    expect(screen.queryByText(/WORKER_API_KEY/)).not.toBeInTheDocument();
  });

  it("renders nothing for a non-admin - never even queries the endpoint", async () => {
    mockRole = "ANALYST";
    renderBanner();

    expect(screen.queryByText(/placeholder secret/i)).not.toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  it("renders nothing once both secrets have been rotated", async () => {
    mockedApiFetch.mockResolvedValue(
      jsonResponse(status({ jwtSigningKeyIsPlaceholder: false, workerApiKeyIsPlaceholder: false })),
    );
    renderBanner();

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalled());
    expect(screen.queryByText(/placeholder secret/i)).not.toBeInTheDocument();
  });

  // The actual point of this test: dismissal is delegated to authBridge (via useAuth), not owned
  // as local component state - see the component's own doc comment for the live bug this fixes
  // (every page wraps its own fresh <Shell>, so local state reset on every navigation, not just
  // at login). This only asserts the component's own contract: call through on click.
  it("clicking dismiss calls dismissSecurityBanner", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValue(jsonResponse(status()));
    renderBanner();

    await waitFor(() => expect(screen.getByText(/placeholder secrets still in use/i)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /dismiss security warning/i }));

    expect(mockDismissSecurityBanner).toHaveBeenCalledTimes(1);
  });

  it("renders nothing when the security banner was already dismissed", async () => {
    mockDismissed = true;
    mockedApiFetch.mockResolvedValue(jsonResponse(status()));
    renderBanner();

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalled());
    expect(screen.queryByText(/placeholder secret/i)).not.toBeInTheDocument();
  });
});
