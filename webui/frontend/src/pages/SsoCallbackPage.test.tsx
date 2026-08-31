import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SsoCallbackPage } from "./SsoCallbackPage";

const completeSsoLogin = vi.fn();
vi.mock("../lib/useAuth", () => ({
  useAuth: () => ({ completeSsoLogin }),
}));
vi.mock("../components/Shell", () => ({ Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

function renderPage(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/sso/callback" element={<SsoCallbackPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("SsoCallbackPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the server's specific error message for a misconfigured IdP, without attempting a code exchange", async () => {
    // SamlAuthenticationSuccessHandler redirects here with ?error=... (not ?code=...) when the
    // registrationId is unrecognized or the assertion is missing the configured email attribute -
    // this must show that specific, actionable message rather than the generic "no code" fallback.
    renderPage(
      "/sso/callback?error=" +
        encodeURIComponent("SSO configuration error: unrecognized identity provider. Contact your administrator."),
    );

    expect(
      await screen.findByText("SSO configuration error: unrecognized identity provider. Contact your administrator."),
    ).toBeInTheDocument();
    expect(completeSsoLogin).not.toHaveBeenCalled();
  });

  it("falls back to the generic missing-code message when neither error nor code is present", async () => {
    renderPage("/sso/callback");

    expect(await screen.findByText("No SSO code was present in the callback URL.")).toBeInTheDocument();
    expect(completeSsoLogin).not.toHaveBeenCalled();
  });

  it("still completes a normal successful SSO login via the code param", async () => {
    completeSsoLogin.mockResolvedValueOnce(undefined);

    renderPage("/sso/callback?code=abc123");

    await waitFor(() => expect(completeSsoLogin).toHaveBeenCalledWith("abc123"));
  });
});
