import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { RequireAuth } from "./RequireAuth";

const mockUseAuth = vi.fn();
vi.mock("../lib/useAuth", () => ({ useAuth: () => mockUseAuth() }));

function renderGuarded() {
  return render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <Routes>
        <Route path="/dashboard" element={<RequireAuth>protected content</RequireAuth>} />
        <Route path="/login" element={<div>login page</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("RequireAuth", () => {
  it("shows a loading state and not the protected content while auth status is loading", () => {
    mockUseAuth.mockReturnValue({ status: "loading" });

    renderGuarded();

    expect(screen.getByText(/checking session/i)).toBeInTheDocument();
    expect(screen.queryByText("protected content")).not.toBeInTheDocument();
  });

  it("redirects to /login when unauthenticated", () => {
    mockUseAuth.mockReturnValue({ status: "unauthenticated" });

    renderGuarded();

    expect(screen.getByText("login page")).toBeInTheDocument();
    expect(screen.queryByText("protected content")).not.toBeInTheDocument();
  });

  it("renders children when authenticated", () => {
    mockUseAuth.mockReturnValue({ status: "authenticated" });

    renderGuarded();

    expect(screen.getByText("protected content")).toBeInTheDocument();
  });
});
