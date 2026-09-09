import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";

const MENU_LINK_CLASS =
  "block px-4 py-2 font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:bg-void/60 hover:text-neon-cyan aria-[current=page]:text-neon-cyan";

/**
 * A product/UX review found the top nav had grown to 10 links plus the notification bell and
 * search - Admin/API Keys/Sessions/Change password/Log out are all "manage my own account or
 * this org" concerns, not day-to-day navigation, and sitting in the same row as Dashboard/
 * Targets/Findings made the primary nav read as cluttered. Consolidated into one dropdown here,
 * mirroring NotificationCenter/QuickTargetSearch's own open/close/backdrop/Escape pattern.
 *
 * <p>Rendered outside the `hidden lg:flex` desktop-only nav wrapper (same level as
 * NotificationCenter/QuickTargetSearch in Shell.tsx), so it's reachable on mobile too - the
 * items it now owns were previously only reachable via Shell's separate hamburger menu.
 */
export function AccountMenu({
  isAdmin,
  onChangePassword,
  onLogout,
}: {
  isAdmin: boolean;
  onChangePassword: () => void;
  onLogout: () => void;
}) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  return (
    <div className="relative">
      {/* relative z-50, matching NotificationCenter's own fix for the identical issue: without
          it, the open panel's backdrop (z-40, later in paint order) would swallow a second click
          on this button meant to close the panel the same way the first one opened it. */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="relative z-50 flex items-center gap-1.5 font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan"
        aria-label="Account menu"
        aria-expanded={open}
        aria-haspopup="menu"
      >
        <span aria-hidden>⚙</span>
        <span className="hidden sm:inline">Account</span>
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} aria-hidden />
          <div
            role="menu"
            aria-label="Account menu"
            className="absolute right-0 top-8 z-50 w-52 overflow-hidden rounded-lg border border-neon-cyan/20 bg-panel py-1 shadow-glow-cyan"
          >
            <NavLink role="menuitem" to="/settings/api-keys" className={MENU_LINK_CLASS} onClick={() => setOpen(false)}>
              API Keys
            </NavLink>
            <NavLink role="menuitem" to="/settings/sessions" className={MENU_LINK_CLASS} onClick={() => setOpen(false)}>
              Sessions
            </NavLink>
            {isAdmin && (
              <NavLink role="menuitem" to="/admin/users" className={MENU_LINK_CLASS} onClick={() => setOpen(false)}>
                Admin
              </NavLink>
            )}
            <button
              role="menuitem"
              onClick={() => {
                onChangePassword();
                setOpen(false);
              }}
              className={`${MENU_LINK_CLASS} w-full text-left`}
            >
              Change password
            </button>
            <div className="my-1 border-t border-slate-700" aria-hidden />
            <button
              role="menuitem"
              onClick={() => {
                onLogout();
                setOpen(false);
              }}
              className={`${MENU_LINK_CLASS} w-full text-left`}
            >
              Log out
            </button>
          </div>
        </>
      )}
    </div>
  );
}
