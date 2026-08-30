import { useEffect } from "react";

/**
 * Warns before an accidental tab close/reload/URL-bar navigation discards unsaved edits.
 *
 * A product/UX review found long, effortful forms in this app (SSO's IdP config in particular -
 * an X.509 certificate pasted from an IdP admin console, an entity ID, an SSO URL) had no
 * protection against losing that work to a stray Cmd+W, browser back, or accidental refresh - the
 * kind of mistake that's cheap for a two-field form but genuinely costly to redo here. The
 * standard `beforeunload` confirmation is deliberately the only mechanism (not a React Router
 * navigation blocker for in-app link clicks too) - it's the well-understood, zero-dependency way
 * to cover the browser-level cases that actually destroy unsaved state; in-app SPA navigation
 * (clicking "Dashboard" in the nav) is a smaller, cheaper mistake to recover from by comparison.
 */
export function useUnsavedChangesWarning(hasUnsavedChanges: boolean) {
  useEffect(() => {
    if (!hasUnsavedChanges) return;

    function handleBeforeUnload(e: BeforeUnloadEvent) {
      // Both are set for browser compatibility - modern browsers only need preventDefault(),
      // but returnValue is still what some older/embedded webviews check. Every browser shows
      // its own generic built-in wording regardless of what's assigned here (a long-standing,
      // deliberate anti-abuse restriction on this exact API), so there's no custom message to write.
      e.preventDefault();
      e.returnValue = "";
    }

    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [hasUnsavedChanges]);
}
