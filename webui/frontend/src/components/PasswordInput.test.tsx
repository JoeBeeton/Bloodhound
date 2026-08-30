import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { PasswordInput } from "./PasswordInput";

function Controlled({ initial = "" }: { initial?: string }) {
  const [value, setValue] = useState(initial);
  return <PasswordInput id="pw" label="Password" value={value} onChange={setValue} />;
}

describe("PasswordInput", () => {
  it("defaults to a masked password field", () => {
    render(<PasswordInput id="pw" label="Password" value="secret123" onChange={vi.fn()} />);

    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "password");
    expect(screen.getByRole("button", { name: /show password/i })).toBeInTheDocument();
  });

  it("toggling reveals the value as plain text and flips the button's label", async () => {
    const user = userEvent.setup();
    render(<Controlled initial="secret123" />);

    await user.click(screen.getByRole("button", { name: /show password/i }));

    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "text");
    expect(screen.getByRole("button", { name: /hide password/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /hide password/i }));
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "password");
  });

  it("calls onChange as the user types, without losing characters", async () => {
    const user = userEvent.setup();
    render(<Controlled />);

    await user.type(screen.getByLabelText("Password"), "hunter2");

    expect(screen.getByLabelText("Password")).toHaveValue("hunter2");
  });
});
