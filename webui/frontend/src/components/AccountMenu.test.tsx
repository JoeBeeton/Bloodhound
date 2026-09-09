import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AccountMenu } from "./AccountMenu";

function renderMenu(overrides: Partial<{ isAdmin: boolean; onChangePassword: () => void; onLogout: () => void }> = {}) {
  const onChangePassword = overrides.onChangePassword ?? vi.fn();
  const onLogout = overrides.onLogout ?? vi.fn();
  render(
    <MemoryRouter>
      <AccountMenu isAdmin={overrides.isAdmin ?? false} onChangePassword={onChangePassword} onLogout={onLogout} />
    </MemoryRouter>,
  );
  return { onChangePassword, onLogout };
}

describe("AccountMenu", () => {
  // The actual point of consolidating these into a dropdown - see the component's own doc
  // comment for the nav-declutter motivation.
  it("is closed by default", () => {
    renderMenu();
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("clicking the trigger opens the menu with API Keys, Sessions, Change password, and Log out", async () => {
    const user = userEvent.setup();
    renderMenu();

    await user.click(screen.getByRole("button", { name: /account menu/i }));

    expect(screen.getByRole("menuitem", { name: "API Keys" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Sessions" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Change password" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Log out" })).toBeInTheDocument();
  });

  it("hides the Admin link for a non-admin", async () => {
    const user = userEvent.setup();
    renderMenu({ isAdmin: false });

    await user.click(screen.getByRole("button", { name: /account menu/i }));

    expect(screen.queryByRole("menuitem", { name: "Admin" })).not.toBeInTheDocument();
  });

  it("shows the Admin link for an admin", async () => {
    const user = userEvent.setup();
    renderMenu({ isAdmin: true });

    await user.click(screen.getByRole("button", { name: /account menu/i }));

    expect(screen.getByRole("menuitem", { name: "Admin" })).toBeInTheDocument();
  });

  it("clicking Change password calls the callback and closes the menu", async () => {
    const user = userEvent.setup();
    const { onChangePassword } = renderMenu();
    await user.click(screen.getByRole("button", { name: /account menu/i }));

    await user.click(screen.getByRole("menuitem", { name: "Change password" }));

    expect(onChangePassword).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("clicking Log out calls the callback and closes the menu", async () => {
    const user = userEvent.setup();
    const { onLogout } = renderMenu();
    await user.click(screen.getByRole("button", { name: /account menu/i }));

    await user.click(screen.getByRole("menuitem", { name: "Log out" }));

    expect(onLogout).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("Escape closes the menu", async () => {
    const user = userEvent.setup();
    renderMenu();
    await user.click(screen.getByRole("button", { name: /account menu/i }));
    expect(screen.getByRole("menu")).toBeInTheDocument();

    await user.keyboard("{Escape}");

    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
  });

  it("clicking the backdrop outside the panel closes the menu", async () => {
    const user = userEvent.setup();
    const { container } = render(
      <MemoryRouter>
        <AccountMenu isAdmin={false} onChangePassword={vi.fn()} onLogout={vi.fn()} />
      </MemoryRouter>,
    );
    await user.click(screen.getByRole("button", { name: /account menu/i }));
    expect(screen.getByRole("menu")).toBeInTheDocument();

    // The invisible full-screen backdrop, not the panel itself - same technique
    // NotificationCenter/QuickTargetSearch/Modal already use for "click outside to close".
    const backdrop = container.querySelector('[aria-hidden="true"].fixed.inset-0');
    expect(backdrop).not.toBeNull();
    await user.click(backdrop!);

    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });
});
