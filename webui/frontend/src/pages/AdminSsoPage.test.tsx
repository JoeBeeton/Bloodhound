import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { AdminSsoPage } from "./AdminSsoPage";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/AdminSubNav", () => ({ AdminSubNav: () => <div /> }));
vi.mock("../lib/useAuth", () => ({ useAuth: () => ({ user: { organizationId: "org-1", role: "ADMIN" } }) }));

const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function ssoConfig(overrides: Record<string, unknown> = {}) {
  return {
    registrationId: "acme-corp",
    idpEntityId: "https://idp.example.com/entity",
    idpSsoUrl: "https://idp.example.com/sso",
    idpX509Cert: "MIIB...cert...",
    emailAttributeName: "email",
    displayNameAttributeName: null,
    enabled: true,
    spEntityId: "https://app.example/saml/acme-corp",
    spAcsUrl: "https://app.example/saml/acme-corp/acs",
    ssoLoginUrl: "https://app.example/login/saml/acme-corp",
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminSsoPage />
    </QueryClientProvider>,
  );
}

describe("AdminSsoPage - unsaved changes warning", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows no 'unsaved changes' indicator right after loading", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(ssoConfig()));

    renderPage();

    await screen.findByDisplayValue("https://idp.example.com/entity", {}, { timeout: 5000 });
    expect(screen.queryByText("Unsaved changes.")).not.toBeInTheDocument();
  });

  it("shows the indicator once a field is edited", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(ssoConfig()));

    renderPage();
    const entityIdInput = await screen.findByDisplayValue("https://idp.example.com/entity", {}, { timeout: 5000 });

    await user.type(entityIdInput, "-edited");

    expect(await screen.findByText("Unsaved changes.")).toBeInTheDocument();
  });

  it("clears the indicator once the edit is reverted back to the saved value", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(ssoConfig()));

    renderPage();
    const entityIdInput = await screen.findByDisplayValue("https://idp.example.com/entity", {}, { timeout: 5000 });

    await user.type(entityIdInput, "x");
    await screen.findByText("Unsaved changes.");
    await user.type(entityIdInput, "{backspace}");

    expect(screen.queryByText("Unsaved changes.")).not.toBeInTheDocument();
  });

  it("clears the indicator once the change is saved", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse(ssoConfig())) // load
      .mockResolvedValueOnce(jsonResponse(ssoConfig({ idpEntityId: "https://idp.example.com/entity-edited" }))); // save

    renderPage();
    const entityIdInput = await screen.findByDisplayValue("https://idp.example.com/entity", {}, { timeout: 5000 });

    await user.type(entityIdInput, "-edited");
    await screen.findByText("Unsaved changes.");

    await user.click(screen.getByRole("button", { name: /save/i }));

    await screen.findByText("Saved ✓", {}, { timeout: 5000 });
    expect(screen.queryByText("Unsaved changes.")).not.toBeInTheDocument();
  });
});
