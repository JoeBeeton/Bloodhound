import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { Modal } from "./Modal";

describe("Modal", () => {
  it("exposes dialog role, aria-modal, and a name pointing at the visible title", () => {
    render(
      <Modal title="Confirm thing" onClose={() => {}}>
        <p>body</p>
      </Modal>,
    );

    const dialog = screen.getByRole("dialog", { name: "Confirm thing" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("moves focus into the dialog on open", () => {
    render(
      <Modal title="Confirm thing" onClose={() => {}}>
        <p>body</p>
      </Modal>,
    );

    expect(screen.getByRole("dialog")).toHaveFocus();
  });

  it("Escape calls onClose", () => {
    const onClose = vi.fn();
    render(
      <Modal title="Confirm thing" onClose={onClose}>
        <p>body</p>
      </Modal>,
    );

    fireEvent.keyDown(document, { key: "Escape" });

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("clicking the backdrop calls onClose, but clicking inside the panel does not", () => {
    const onClose = vi.fn();
    render(
      <Modal title="Confirm thing" onClose={onClose}>
        <p>body text</p>
      </Modal>,
    );

    fireEvent.click(screen.getByText("body text"));
    expect(onClose).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("dialog").parentElement!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("Tab from the last focusable element wraps to the first (the close button)", () => {
    render(
      <Modal title="Confirm thing" onClose={() => {}}>
        <button>Cancel</button>
        <button>Confirm</button>
      </Modal>,
    );

    const closeButton = screen.getByRole("button", { name: "Close" });
    const confirmButton = screen.getByRole("button", { name: "Confirm" });
    confirmButton.focus();

    fireEvent.keyDown(document, { key: "Tab" });

    expect(closeButton).toHaveFocus();
  });

  it("Shift+Tab from the first focusable element wraps to the last", () => {
    render(
      <Modal title="Confirm thing" onClose={() => {}}>
        <button>Cancel</button>
        <button>Confirm</button>
      </Modal>,
    );

    const closeButton = screen.getByRole("button", { name: "Close" });
    const confirmButton = screen.getByRole("button", { name: "Confirm" });
    closeButton.focus();

    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });

    expect(confirmButton).toHaveFocus();
  });

  it("restores focus to whatever triggered the modal once it unmounts", () => {
    // Regression coverage for the actual gap a product/AppSec review found: opening a modal
    // previously left focus wherever it already was, so a keyboard user tabbing after closing
    // one landed back in the middle of the page rather than continuing from the control they
    // opened it with.
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <div>
          <button onClick={() => setOpen(true)}>Open</button>
          {open && (
            <Modal title="Confirm thing" onClose={() => setOpen(false)}>
              <p>body</p>
            </Modal>
          )}
        </div>
      );
    }
    render(<Harness />);

    const openButton = screen.getByRole("button", { name: "Open" });
    openButton.focus();
    fireEvent.click(openButton);
    expect(screen.getByRole("dialog")).toHaveFocus();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(openButton).toHaveFocus();
  });
});
