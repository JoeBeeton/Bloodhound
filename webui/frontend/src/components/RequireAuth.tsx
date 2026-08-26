import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../lib/useAuth";
import { CenteredState } from "./CenteredState";
import { Shell } from "./Shell";

export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth();

  if (status === "loading") {
    return (
      <Shell>
        <CenteredState>
          <p className="font-mono text-sm uppercase tracking-widest text-slate-400">Checking session…</p>
        </CenteredState>
      </Shell>
    );
  }

  if (status === "unauthenticated") {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
