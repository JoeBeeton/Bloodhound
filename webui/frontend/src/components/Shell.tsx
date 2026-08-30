import { useEffect, useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../lib/useAuth";
import { useIdleLogout } from "../lib/useIdleLogout";
import { BloodhoundMascot } from "./BloodhoundMascot";
import { ChangePasswordModal } from "./ChangePasswordModal";
import { GridHorizon } from "./GridHorizon";
import { Modal } from "./Modal";
import { NotificationCenter } from "./NotificationCenter";
import { SecurityStatusBanner } from "./SecurityStatusBanner";

const NAV_LINK_CLASS =
  "font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan aria-[current=page]:text-neon-cyan";

// A product/AppSec review found no idle-session timeout existed at all, despite the app's own
// design implying one (a 15-minute access token meant to go quiet on an abandoned tab) -
// NotificationCenter's unconditional 25s polling kept every open tab silently re-authenticated
// forever regardless of whether anyone was actually there, up to the 90-day absolute session
// cap. 30 minutes of real inactivity (mouse/keyboard/touch/scroll - see useIdleLogout) now forces
// a logout, with a 60s warning first so a person just reading a long report isn't cut off
// mid-thought with no chance to say "I'm still here".
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const IDLE_WARNING_MS = 60 * 1000;

/** Shared page chrome (background + logo header, nav once authenticated) every screen renders inside. */
export function Shell({ children }: { children: ReactNode }) {
  const { status, logout, user } = useAuth();
  const [showChangePassword, setShowChangePassword] = useState(false);
  // A product/AppSec review found the nav had no mobile handling at all: 9 links plus the
  // notification bell in one non-wrapping row overflowed every viewport under ~1000px wide,
  // pushing Dashboard, Change password, Log out, and the notification bell off-screen with no
  // visible way to reach them short of an undiscovered horizontal scroll - confirmed live via a
  // real 375px-viewport screenshot. Below lg, the link list collapses behind this toggle instead.
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [idleWarning, setIdleWarning] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(IDLE_WARNING_MS / 1000);

  function closeMobileMenu() {
    setMobileMenuOpen(false);
  }

  useIdleLogout({
    enabled: status === "authenticated",
    idleTimeoutMs: IDLE_TIMEOUT_MS,
    warningMs: IDLE_WARNING_MS,
    onWarn: () => {
      setSecondsLeft(IDLE_WARNING_MS / 1000);
      setIdleWarning(true);
    },
    onTimeout: () => {
      setIdleWarning(false);
      logout();
    },
  });

  // Countdown display only - useIdleLogout's own interval is what actually decides when to log
  // out, this just ticks the number shown in the warning modal down once a second.
  useEffect(() => {
    if (!idleWarning) return;
    const interval = window.setInterval(() => setSecondsLeft((s) => Math.max(0, s - 1)), 1000);
    return () => window.clearInterval(interval);
  }, [idleWarning]);

  const navLinks = (
    <>
      <NavLink to="/dashboard" className={NAV_LINK_CLASS} onClick={closeMobileMenu}>
        Dashboard
      </NavLink>
      <NavLink to="/targets" className={NAV_LINK_CLASS} onClick={closeMobileMenu}>
        Targets
      </NavLink>
      <NavLink to="/findings" className={NAV_LINK_CLASS} onClick={closeMobileMenu}>
        Findings
      </NavLink>
      <NavLink to="/map" className={NAV_LINK_CLASS} onClick={closeMobileMenu}>
        Map
      </NavLink>
      <NavLink to="/scans" className={NAV_LINK_CLASS} onClick={closeMobileMenu}>
        Scans
      </NavLink>
      <NavLink to="/compare" className={NAV_LINK_CLASS} onClick={closeMobileMenu}>
        Compare
      </NavLink>
      <NavLink to="/settings/api-keys" className={NAV_LINK_CLASS} onClick={closeMobileMenu}>
        API Keys
      </NavLink>
      {user?.role === "ADMIN" && (
        <NavLink to="/admin/users" className={NAV_LINK_CLASS} onClick={closeMobileMenu}>
          Admin
        </NavLink>
      )}
      <button
        onClick={() => {
          setShowChangePassword(true);
          closeMobileMenu();
        }}
        className={`${NAV_LINK_CLASS} text-left`}
      >
        Change password
      </button>
      <button
        onClick={() => {
          logout();
          closeMobileMenu();
        }}
        className={`${NAV_LINK_CLASS} text-left`}
      >
        Log out
      </button>
    </>
  );

  return (
    <div className="relative min-h-screen bg-void">
      <GridHorizon />
      <div className="relative z-10 flex min-h-screen flex-col">
        <header className="flex items-center justify-between gap-4 px-6 py-6">
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
            <div className="flex items-center gap-4">
              <nav className="hidden items-center gap-5 lg:flex">{navLinks}</nav>
              <NotificationCenter />
              <button
                onClick={() => setMobileMenuOpen((v) => !v)}
                aria-expanded={mobileMenuOpen}
                aria-label={mobileMenuOpen ? "Close menu" : "Open menu"}
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded border border-slate-700 text-slate-300 transition hover:border-neon-cyan/50 hover:text-neon-cyan lg:hidden"
              >
                <span aria-hidden="true">{mobileMenuOpen ? "✕" : "☰"}</span>
              </button>
            </div>
          )}
        </header>
        {status === "authenticated" && mobileMenuOpen && (
          <nav className="flex flex-col items-start gap-4 border-y border-neon-cyan/10 bg-panel/95 px-6 py-4 lg:hidden">
            {navLinks}
          </nav>
        )}
        {status === "authenticated" && <SecurityStatusBanner />}
        {/* Top-aligned, not vertically centered: this chrome wraps every screen, most of
            which (targets list, findings, compare charts) are taller than the viewport.
            Screens that want a centered card (login, transient full-page states) opt in
            themselves via <CenteredState>/their own flex-1 wrapper, same pattern LoginPage uses. */}
        <main className="flex flex-1 flex-col items-center gap-4 px-6 pb-16">{children}</main>
      </div>
      {showChangePassword && <ChangePasswordModal onClose={() => setShowChangePassword(false)} />}
      {idleWarning && (
        <Modal title="Still there?" onClose={() => setIdleWarning(false)}>
          <p className="mb-4 text-sm text-slate-300">
            You've been inactive for a while. For your security, you'll be signed out in{" "}
            <span className="font-mono font-bold text-neon-amber">{secondsLeft}s</span> unless you confirm you're
            still here.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => logout()}
              className="flex-1 rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 transition hover:border-slate-500"
            >
              Log out now
            </button>
            {/* This click is itself real activity (a window mousedown), so useIdleLogout's own
                clock has already reset by the time this handler runs - explicitly closing the
                modal here just clears this component's display state to match. */}
            <button
              onClick={() => setIdleWarning(false)}
              className="flex-1 rounded bg-neon-cyan/90 px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-cyan"
            >
              Stay signed in
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
