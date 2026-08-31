import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import type { Finding } from "../lib/types";
import { FindingDetailModal } from "./FindingDetailModal";

vi.mock("../lib/apiClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/apiClient")>()),
  apiFetch: vi.fn(),
}));

let mockRole = "ANALYST";
vi.mock("../lib/useAuth", () => ({ useAuth: () => ({ user: { role: mockRole } }) }));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    displayId: "bh-example.com-1",
    targetId: "t1",
    moduleType: "HTTP_HEADERS",
    ruleId: "MISSING_CSP",
    severity: "MEDIUM",
    category: "HEADERS",
    title: "Missing Content-Security-Policy header",
    description: "No CSP header was present.",
    evidence: {},
    affectedAsset: "example.com",
    firstDetectedScanRunId: "run1",
    status: "OPEN",
    resolvedAt: null,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    firstSeenAt: "2026-01-01T00:00:00Z",
    lastSeenAt: "2026-01-01T00:00:00Z",
    remediationAdvice: null,
    scoreImpact: null,
    ...overrides,
  };
}

function renderModal(f: Finding, onClose = vi.fn()) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <FindingDetailModal finding={f} onClose={onClose} />
    </QueryClientProvider>,
  );
  return { onClose, queryClient };
}

describe("FindingDetailModal - dismiss/reopen", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "ANALYST";
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows Dismiss for an OPEN finding when the caller has write access", () => {
    renderModal(finding({ status: "OPEN" }));

    expect(screen.getByRole("button", { name: "Dismiss" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reopen" })).not.toBeInTheDocument();
  });

  it("shows Reopen for a DISMISSED finding", () => {
    renderModal(finding({ status: "DISMISSED" }));

    expect(screen.getByRole("button", { name: "Reopen" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
  });

  it("shows neither action for a RESOLVED finding", () => {
    renderModal(finding({ status: "RESOLVED" }));

    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reopen" })).not.toBeInTheDocument();
  });

  it("hides Dismiss for a VIEWER, even on an open finding", () => {
    mockRole = "VIEWER";
    renderModal(finding({ status: "OPEN" }));

    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
  });

  it("clicking Dismiss calls the dismiss endpoint and closes the modal on success", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response);
    const { onClose } = renderModal(finding({ status: "OPEN" }));

    await user.click(screen.getByRole("button", { name: "Dismiss" }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/findings/f1/dismiss", { method: "POST" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it("clicking Reopen calls the reopen endpoint and closes the modal on success", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response);
    const { onClose } = renderModal(finding({ status: "DISMISSED" }));

    await user.click(screen.getByRole("button", { name: "Reopen" }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/findings/f1/reopen", { method: "POST" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it("a 409 (e.g. a race) shows the server's real message and does not close the modal", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(
      jsonResponse({ message: "only an open finding can be dismissed" }, { ok: false, status: 409 }),
    );
    const { onClose } = renderModal(finding({ status: "OPEN" }));

    await user.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(await screen.findByText("only an open finding can be dismissed")).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });
});
