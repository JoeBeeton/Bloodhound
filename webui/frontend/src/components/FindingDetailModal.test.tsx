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
    statusReason: null,
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

describe("FindingDetailModal - evidence", () => {
  it("renders a URL-shaped evidence value as a clickable link", () => {
    renderModal(finding({ evidence: { status: 200, url: "https://example.com/v3/api-docs" } }));

    const link = screen.getByRole("link", { name: "https://example.com/v3/api-docs" });
    expect(link).toHaveAttribute("href", "https://example.com/v3/api-docs");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    // A non-URL value in the same evidence blob stays plain text, not a link.
    expect(screen.queryByRole("link", { name: "200" })).not.toBeInTheDocument();
  });

  it("does not linkify a non-http(s) string even if evidence calls it a url", () => {
    renderModal(finding({ evidence: { url: "javascript:alert(1)" } }));

    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("javascript:alert(1)")).toBeInTheDocument();
  });

  it("renders a URL-shaped affectedAsset (ZAP/Nuclei findings) as a clickable link", () => {
    renderModal(finding({ affectedAsset: "https://example.com/actuator/health" }));

    const link = screen.getByRole("link", { name: "https://example.com/actuator/health" });
    expect(link).toHaveAttribute("href", "https://example.com/actuator/health");
  });

  it("keeps a bare-hostname affectedAsset as plain text", () => {
    renderModal(finding({ affectedAsset: "example.com" }));

    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("example.com")).toBeInTheDocument();
  });
});

describe("FindingDetailModal - dismiss/reopen", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "ANALYST";
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows Dismiss and Accept Risk for an OPEN finding when the caller has write access", () => {
    renderModal(finding({ status: "OPEN" }));

    expect(screen.getByRole("button", { name: "Dismiss" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Accept Risk" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reopen" })).not.toBeInTheDocument();
  });

  it("shows Reopen for a DISMISSED finding", () => {
    renderModal(finding({ status: "DISMISSED" }));

    expect(screen.getByRole("button", { name: "Reopen" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
  });

  it("shows Reopen for an ACCEPTED_RISK finding", () => {
    renderModal(finding({ status: "ACCEPTED_RISK" }));

    expect(screen.getByRole("button", { name: "Reopen" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Accept Risk" })).not.toBeInTheDocument();
  });

  it("shows neither action for a RESOLVED finding", () => {
    renderModal(finding({ status: "RESOLVED" }));

    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Accept Risk" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reopen" })).not.toBeInTheDocument();
  });

  it("hides Dismiss and Accept Risk for a VIEWER, even on an open finding", () => {
    mockRole = "VIEWER";
    renderModal(finding({ status: "OPEN" }));

    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Accept Risk" })).not.toBeInTheDocument();
  });

  it("clicking Dismiss with no reason typed sends a null reason and closes the modal on success", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response);
    const { onClose } = renderModal(finding({ status: "OPEN" }));

    await user.click(screen.getByRole("button", { name: "Dismiss" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/findings/f1/dismiss", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: null }),
      }),
    );
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it("typing a reason and clicking Dismiss sends it in the request body", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response);
    renderModal(finding({ status: "OPEN" }));

    await user.type(screen.getByLabelText(/Reason/i), "false positive, third-party CDN");
    await user.click(screen.getByRole("button", { name: "Dismiss" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/findings/f1/dismiss", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "false positive, third-party CDN" }),
      }),
    );
  });

  it("clicking Accept Risk calls the accept-risk endpoint and closes the modal on success", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response);
    const { onClose } = renderModal(finding({ status: "OPEN" }));

    await user.type(screen.getByLabelText(/Reason/i), "risk accepted, compensating control in place");
    await user.click(screen.getByRole("button", { name: "Accept Risk" }));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/findings/f1/accept-risk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "risk accepted, compensating control in place" }),
      }),
    );
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

  it("shows a dismissed finding's recorded reason", () => {
    renderModal(finding({ status: "DISMISSED", statusReason: "false positive, third-party CDN" }));

    expect(screen.getByText("false positive, third-party CDN")).toBeInTheDocument();
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
