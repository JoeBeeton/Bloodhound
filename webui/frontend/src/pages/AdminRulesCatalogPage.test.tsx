import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { AdminRulesCatalogPage } from "./AdminRulesCatalogPage";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/AdminSubNav", () => ({ AdminSubNav: () => <div /> }));
vi.mock("../lib/useAuth", () => ({
  useAuth: () => ({ status: "authenticated", user: { organizationId: "org-1", role: "ADMIN" } }),
}));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body, text: async () => "" } as Response;
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminRulesCatalogPage />
    </QueryClientProvider>,
  );
}

const RULE = {
  ruleId: "DNS_SPF_MISSING",
  category: "DNS",
  defaultSeverity: "HIGH" as const,
  title: "Missing SPF record",
  description: "desc",
  remediationAdvice: "fix it",
  weight: 1,
  enabled: true,
};

describe("AdminRulesCatalogPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // A security review found the old PATCH URL (/api/v1/rules-catalog/{ruleId}) updated a single
  // global row with no organization scoping - any org's admin toggling a rule affected every
  // tenant. The fix moved this to an org-scoped path; this is the regression guard for that -
  // toggling a rule must always target the current user's own org id in the URL.
  it("toggling a rule PATCHes the org-scoped URL, not the old bare one", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse([RULE]))
      .mockResolvedValueOnce(jsonResponse({ ...RULE, enabled: false }));

    renderPage();
    await screen.findByText("Missing SPF record");

    await user.click(screen.getByRole("checkbox"));

    await waitFor(() =>
      expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/orgs/org-1/rules-catalog/DNS_SPF_MISSING", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: false }),
      }),
    );
  });
});
