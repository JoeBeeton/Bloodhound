import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { RequireAdmin } from "./RequireAdmin";

const mockUseAuth = vi.fn();
vi.mock("../lib/useAuth", () => ({ useAuth: () => mockUseAuth() }));

function renderGuarded() {
  return render(
    <MemoryRouter initialEntries={["/admin/users"]}>
      <Routes>
        <Route path="/admin/users" element={<RequireAdmin>admin-only content</RequireAdmin>} />
        <Route path="/dashboard" element={<div>dashboard page</div>} />
        <Route path="/login" element={<div>login page</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("RequireAdmin", () => {
  it("redirects to /login when unauthenticated (delegates to RequireAuth)", () => {
    mockUseAuth.mockReturnValue({ status: "unauthenticated" });

    renderGuarded();

    expect(screen.getByText("login page")).toBeInTheDocument();
  });

  it("redirects a non-admin (VIEWER) to /dashboard rather than showing admin content", () => {
    mockUseAuth.mockReturnValue({ status: "authenticated", user: { role: "VIEWER" } });

    renderGuarded();

    expect(screen.getByText("dashboard page")).toBeInTheDocument();
    expect(screen.queryByText("admin-only content")).not.toBeInTheDocument();
  });

  it("redirects a non-admin (ANALYST) to /dashboard too - ADMIN is the only role let through", () => {
    mockUseAuth.mockReturnValue({ status: "authenticated", user: { role: "ANALYST" } });

    renderGuarded();

    expect(screen.getByText("dashboard page")).toBeInTheDocument();
  });

  it("renders admin content for an ADMIN user", () => {
    mockUseAuth.mockReturnValue({ status: "authenticated", user: { role: "ADMIN" } });

    renderGuarded();

    expect(screen.getByText("admin-only content")).toBeInTheDocument();
  });
});
