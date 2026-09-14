import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { byMostSevereFindingsFirst, SubdomainsPage } from "./SubdomainsPage";
import type { Finding, Severity, Subdomain } from "../lib/types";

vi.mock("../lib/apiClient", async () => {
  const actual = await vi.importActual<typeof import("../lib/apiClient")>("../lib/apiClient");
  return { ...actual, apiFetch: vi.fn() };
});
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

function subdomain(hostname: string): Subdomain {
  return {
    id: hostname,
    hostname,
    firstSeenAt: "2026-01-01T00:00:00Z",
    lastSeenAt: "2026-01-01T00:00:00Z",
    source: "crt.sh",
    isActive: true,
    currentIpAddresses: [],
    wafVendor: null,
    wafScanned: false,
  };
}

function finding(affectedAsset: string, severity: Severity): Finding {
  return {
    id: `${affectedAsset}-${severity}`,
    displayId: `bh-${affectedAsset}-1`,
    targetId: "target-1",
    moduleType: "tls",
    ruleId: "rule",
    severity,
    category: "TLS",
    title: "test finding",
    description: "",
    evidence: {},
    affectedAsset,
    firstDetectedScanRunId: "run-1",
    status: "OPEN",
    resolvedAt: null,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    firstSeenAt: "2026-01-01T00:00:00Z",
  } as Finding;
}

function byHostname(...findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = map.get(f.affectedAsset) ?? [];
    list.push(f);
    map.set(f.affectedAsset, list);
  }
  return map;
}

describe("byMostSevereFindingsFirst", () => {
  it("ranks a CRITICAL finding above a HIGH finding, regardless of input order", () => {
    const rows = [subdomain("low-risk.example.com"), subdomain("critical.example.com")];
    const findings = byHostname(finding("low-risk.example.com", "HIGH"), finding("critical.example.com", "CRITICAL"));
    const sorted = byMostSevereFindingsFirst(rows, findings);
    expect(sorted.map((s) => s.hostname)).toEqual(["critical.example.com", "low-risk.example.com"]);
  });

  it("breaks a severity tie by finding count", () => {
    const rows = [subdomain("one-high.example.com"), subdomain("three-high.example.com")];
    const findings = byHostname(
      finding("one-high.example.com", "HIGH"),
      finding("three-high.example.com", "HIGH"),
      finding("three-high.example.com", "HIGH"),
      finding("three-high.example.com", "HIGH"),
    );
    const sorted = byMostSevereFindingsFirst(rows, findings);
    expect(sorted.map((s) => s.hostname)).toEqual(["three-high.example.com", "one-high.example.com"]);
  });

  it("sinks a clean subdomain (no findings at all) to the bottom", () => {
    const rows = [subdomain("clean.example.com"), subdomain("info-only.example.com")];
    const findings = byHostname(finding("info-only.example.com", "INFO"));
    const sorted = byMostSevereFindingsFirst(rows, findings);
    expect(sorted.map((s) => s.hostname)).toEqual(["info-only.example.com", "clean.example.com"]);
  });

  it("does not mutate the input array", () => {
    const rows = [subdomain("b.example.com"), subdomain("a.example.com")];
    const original = [...rows];
    byMostSevereFindingsFirst(rows, byHostname(finding("a.example.com", "CRITICAL")));
    expect(rows).toEqual(original);
  });
});

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number; totalCount?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    headers: new Headers(init.totalCount !== undefined ? { "X-Total-Count": String(init.totalCount) } : {}),
    json: async () => body,
  } as Response;
}

function renderAt(path: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/targets/:id/subdomains" element={<SubdomainsPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Routes every apiFetch call by URL shape rather than call order - the page's target,
 * subdomains, fingerprints, and findings queries all fire from sibling useQuery calls, whose
 * resolution order isn't guaranteed (same reasoning ScansPage's own tests document). Checked
 * most-specific-path-first since "/subdomains/export" and "/subdomains?" both contain "/subdomains". */
function mockApiRoutes(overrides: {
  subdomains?: Subdomain[];
  export?: { ok: boolean; status?: number };
}) {
  const mockedApiFetch = vi.mocked(apiFetch);
  mockedApiFetch.mockImplementation(async (url) => {
    const href = url.toString();
    if (href.includes("/subdomains/export")) {
      const exportInit = overrides.export ?? { ok: true };
      if (!exportInit.ok) return jsonResponse(null, { ok: false, status: exportInit.status ?? 500 });
      return {
        ok: true,
        headers: new Headers({ "Content-Disposition": 'attachment; filename="example.com-subdomains-2026-01-01.csv"' }),
        blob: async () => new Blob(["Hostname,Status,Source,IP Addresses,First Seen,Last Seen\r\n"], { type: "text/csv" }),
      } as unknown as Response;
    }
    if (href.includes("/fingerprints")) return jsonResponse([]);
    if (href.includes("/findings")) return jsonResponse([], { totalCount: 0 });
    if (href.includes("/subdomains")) {
      const items = overrides.subdomains ?? [];
      return jsonResponse(items, { totalCount: items.length });
    }
    return jsonResponse({ id: "t1", hostname: "example.com" }); // target
  });
  return mockedApiFetch;
}

describe("SubdomainsPage export", () => {
  it("hides the Export CSV button when there are no subdomains yet", async () => {
    mockApiRoutes({ subdomains: [] });

    renderAt("/targets/t1/subdomains");

    await screen.findByText(/no subdomains discovered yet/i);
    expect(screen.queryByRole("button", { name: /export csv/i })).not.toBeInTheDocument();
  });

  it("exporting fetches the export endpoint and triggers a download", async () => {
    const user = userEvent.setup();
    const clickSpy = vi.fn();
    const originalCreateElement = document.createElement.bind(document);
    vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
      const el = originalCreateElement(tag);
      if (tag === "a") el.click = clickSpy;
      return el;
    });
    URL.createObjectURL = vi.fn(() => "blob:subdomains");
    URL.revokeObjectURL = vi.fn();
    mockApiRoutes({ subdomains: [subdomain("a.example.com")] });

    renderAt("/targets/t1/subdomains");
    await screen.findByText("a.example.com");

    await user.click(screen.getByRole("button", { name: /export csv/i }));

    await waitFor(() =>
      expect(vi.mocked(apiFetch)).toHaveBeenCalledWith("/api/v1/targets/t1/subdomains/export?"),
    );
    await waitFor(() => expect(clickSpy).toHaveBeenCalledTimes(1));
    expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:subdomains");
  });

  it("shows an error message when the export request fails, without breaking the page", async () => {
    const user = userEvent.setup();
    mockApiRoutes({ subdomains: [subdomain("a.example.com")], export: { ok: false, status: 500 } });

    renderAt("/targets/t1/subdomains");
    await screen.findByText("a.example.com");

    await user.click(screen.getByRole("button", { name: /export csv/i }));

    expect(await screen.findByText("Failed to export subdomains. Try again.")).toBeInTheDocument();
  });
});
