import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../lib/useAuth";
import { RequireAuth } from "./RequireAuth";

/**
 * Layered on top of RequireAuth: first establishes/waits on auth state (and
 * handles the loading/unauthenticated cases exactly like every other
 * protected route), then additionally redirects non-admins to the dashboard.
 * The Shell's nav also hides these links from non-admins, so this guard is a
 * defense-in-depth backstop for direct navigation, not the only thing
 * standing between a non-admin and these screens - the real enforcement is
 * server-side (@PreAuthorize("hasRole('ADMIN')") on the underlying endpoints).
 */
export function RequireAdmin({ children }: { children: ReactNode }) {
  return (
    <RequireAuth>
      <AdminOnly>{children}</AdminOnly>
    </RequireAuth>
  );
}

function AdminOnly({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  if (user?.role !== "ADMIN") {
    return <Navigate to="/dashboard" replace />;
  }
  return <>{children}</>;
}
