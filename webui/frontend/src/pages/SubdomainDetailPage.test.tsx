import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { SubdomainDetailPage } from "./SubdomainDetailPage";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: async () => body,
  } as Response;
}

function renderAt(path: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/targets/:id/subdomains/:hostname" element={<SubdomainDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const mockedApiFetch = vi.mocked(apiFetch);

describe("SubdomainDetailPage", () => {
  it("shows a clear 'not tracked' message for a hostname the target has no record of (404)", async () => {
    mockedApiFetch.mockImplementation(async (url) => {
      const href = url.toString();
      if (href.includes("/subdomains/")) return jsonResponse(null, { ok: false, status: 404 });
      if (href.includes("/fingerprints")) return jsonResponse([]);
      return jsonResponse([]); // findings
    });

    renderAt("/targets/t1/subdomains/ghost.example.com");

    expect(await screen.findByText("This subdomain isn't tracked for this target.")).toBeInTheDocument();
    // The empty-state sections that used to render regardless of whether the subdomain
    // actually existed must not appear alongside the not-tracked message.
    expect(screen.queryByText(/technology & hosting/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/open findings/i)).not.toBeInTheDocument();
  });

  it("renders the subdomain's metadata and sections when it exists", async () => {
    mockedApiFetch.mockImplementation(async (url) => {
      const href = url.toString();
      if (href.includes("/subdomains/")) {
        return jsonResponse({
          id: "sub-1",
          hostname: "app.example.com",
          firstSeenAt: "2026-01-01T00:00:00Z",
          lastSeenAt: "2026-02-01T00:00:00Z",
          source: "crt.sh",
          isActive: true,
          currentIpAddresses: ["203.0.113.5"],
        });
      }
      if (href.includes("/fingerprints")) return jsonResponse([]);
      return jsonResponse([]); // findings
    });

    renderAt("/targets/t1/subdomains/app.example.com");

    expect(await screen.findByText(/technology & hosting/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /open findings/i })).toBeInTheDocument();
    expect(screen.getByText(/203\.0\.113\.5/)).toBeInTheDocument();
    expect(screen.queryByText("This subdomain isn't tracked for this target.")).not.toBeInTheDocument();
  });
});
