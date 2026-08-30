import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { ChangePasswordModal } from "./ChangePasswordModal";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function renderModal() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <ChangePasswordModal onClose={vi.fn()} />
    </QueryClientProvider>,
  );
}

describe("ChangePasswordModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps the submit button disabled until current password, a long-enough new password, and a matching confirmation are all present", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ count: 1 })); // session count

    renderModal();
    const submit = screen.getByRole("button", { name: "Change password" });
    expect(submit).toBeDisabled();

    await user.type(screen.getByLabelText("Current password"), "oldpass1");
    expect(submit).toBeDisabled();

    await user.type(screen.getByLabelText("New password"), "short");
    expect(submit).toBeDisabled();
    expect(screen.getByText(/at least 8 characters/i)).toHaveClass("text-slate-500");

    await user.type(screen.getByLabelText("New password"), "1234");
    expect(screen.getByText(/at least 8 characters/i)).toHaveClass("text-neon-cyan");
    expect(submit).toBeDisabled(); // confirm field still empty

    await user.type(screen.getByLabelText("Confirm new password"), "mismatch1");
    expect(screen.getByText(/passwords don't match/i)).toBeInTheDocument();
    expect(submit).toBeDisabled();

    await user.clear(screen.getByLabelText("Confirm new password"));
    await user.type(screen.getByLabelText("Confirm new password"), "short1234");
    expect(screen.getByText(/passwords match/i)).toBeInTheDocument();
    expect(submit).toBeEnabled();
  });

  it("submitting a valid change calls the password endpoint and shows the success screen", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse({ count: 1 })) // session count
      .mockResolvedValueOnce(jsonResponse(undefined)); // PATCH password

    renderModal();
    await user.type(screen.getByLabelText("Current password"), "oldpass1");
    await user.type(screen.getByLabelText("New password"), "newpass123");
    await user.type(screen.getByLabelText("Confirm new password"), "newpass123");
    await user.click(screen.getByRole("button", { name: "Change password" }));

    expect(await screen.findByText("Password changed")).toBeInTheDocument();
    const patchCall = mockedApiFetch.mock.calls.find((c) => c[0] === "/api/v1/users/me/password");
    expect(patchCall).toBeDefined();
    expect(JSON.parse((patchCall![1] as RequestInit).body as string)).toEqual({
      currentPassword: "oldpass1",
      newPassword: "newpass123",
    });
  });

  it("shows the incorrect-current-password error from the server and keeps the form open", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse({ count: 1 }))
      .mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 403 }));

    renderModal();
    await user.type(screen.getByLabelText("Current password"), "wrongpass");
    await user.type(screen.getByLabelText("New password"), "newpass123");
    await user.type(screen.getByLabelText("Confirm new password"), "newpass123");
    await user.click(screen.getByRole("button", { name: "Change password" }));

    expect(await screen.findByText("Current password is incorrect.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Change password" })).toBeInTheDocument();
  });

  it("the password fields default masked and can be revealed via the Show toggle", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ count: 1 }));

    renderModal();
    const newPasswordInput = screen.getByLabelText("New password");
    expect(newPasswordInput).toHaveAttribute("type", "password");

    await user.click(screen.getByRole("button", { name: /show new password/i }));
    expect(newPasswordInput).toHaveAttribute("type", "text");
  });

  it("offers to log out other sessions only when there are other active sessions", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ count: 3 }));

    renderModal();

    expect(await screen.findByText(/signed in on 2 other devices too/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Log out other devices" })).toBeInTheDocument();
  });

  it("hides the log-out-others action when this is the only session", async () => {
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ count: 1 }));

    renderModal();

    expect(await screen.findByText(/you're only signed in on this device/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Log out other devices" })).not.toBeInTheDocument();
  });

  it("confirming log-out-others calls the endpoint and updates the session summary", async () => {
    const user = userEvent.setup();
    mockedApiFetch
      .mockResolvedValueOnce(jsonResponse({ count: 3 })) // initial session count
      .mockResolvedValueOnce(jsonResponse(undefined)) // POST logout-others
      .mockResolvedValueOnce(jsonResponse({ count: 1 })); // refetched count

    renderModal();
    await screen.findByText(/signed in on 2 other devices too/i);

    await user.click(screen.getByRole("button", { name: "Log out other devices" }));
    await user.click(screen.getByRole("button", { name: "Confirm sign-out" }));

    expect(await screen.findByText(/you're now only signed in on this device/i)).toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/auth/logout-others", { method: "POST" });
  });
});
