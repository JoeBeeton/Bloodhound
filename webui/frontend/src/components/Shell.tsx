import { useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../lib/useAuth";
import { BloodhoundMascot } from "./BloodhoundMascot";
import { ChangePasswordModal } from "./ChangePasswordModal";
import { GridHorizon } from "./GridHorizon";
import { NotificationCenter } from "./NotificationCenter";

const NAV_LINK_CLASS =
  "font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan aria-[current=page]:text-neon-cyan";

/** Shared page chrome (background + logo header, nav once authenticated) every screen renders inside. */
export function Shell({ children }: { children: ReactNode }) {
  const { status, logout, user } = useAuth();
  const [showChangePassword, setShowChangePassword] = useState(false);

  return (
    <div className="relative min-h-screen bg-void">
      <GridHorizon />
      <div className="relative z-10 flex min-h-screen flex-col">
        <header className="flex flex-col items-center gap-4 px-6 py-6 sm:flex-row sm:justify-between">
          <span className="flex items-center gap-2.5">
            <BloodhoundMascot
              title="Bloodhound"
              className="h-9 w-9 shrink-0"
              style={{ filter: "drop-shadow(0 0 5px rgba(0,240,255,0.55))" }}
            />
            <span
              className="font-display text-lg font-extrabold tracking-widest text-neon-cyan"
              style={{ textShadow: "0 0 8px #00f0ff, 0 0 20px rgba(0,240,255,0.5)" }}
            >
              BLOODHOUND
            </span>
          </span>
          {status === "authenticated" && (
            <nav className="flex items-center gap-5">
              <NavLink to="/dashboard" className={NAV_LINK_CLASS}>
                Dashboard
              </NavLink>
              <NavLink to="/targets" className={NAV_LINK_CLASS}>
                Targets
              </NavLink>
              <NavLink to="/scans" className={NAV_LINK_CLASS}>
                Scans
              </NavLink>
              <NavLink to="/compare" className={NAV_LINK_CLASS}>
                Compare
              </NavLink>
              <NavLink to="/settings/api-keys" className={NAV_LINK_CLASS}>
                API Keys
              </NavLink>
              {user?.role === "ADMIN" && (
                <NavLink to="/admin/users" className={NAV_LINK_CLASS}>
                  Admin
                </NavLink>
              )}
              <button onClick={() => setShowChangePassword(true)} className={NAV_LINK_CLASS}>
                Change password
              </button>
              <button onClick={() => logout()} className={NAV_LINK_CLASS}>
                Log out
              </button>
              <NotificationCenter />
            </nav>
          )}
        </header>
        {/* Top-aligned, not vertically centered: this chrome wraps every screen, most of
            which (targets list, findings, compare charts) are taller than the viewport.
            Screens that want a centered card (login, transient full-page states) opt in
            themselves via <CenteredState>/their own flex-1 wrapper, same pattern LoginPage uses. */}
        <main className="flex flex-1 flex-col items-center gap-4 px-6 pb-16">{children}</main>
      </div>
      {showChangePassword && <ChangePasswordModal onClose={() => setShowChangePassword(false)} />}
    </div>
  );
}
