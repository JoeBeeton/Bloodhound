import { useEffect, useId, useRef, type ReactNode } from "react";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * A simple centered overlay dialog - shared by the remove-target confirmation, add-user,
 * change-password, password-reset, and finding-detail flows.
 *
 * A product/AppSec review found this had none of the behavior a modal needs to actually be
 * modal for a keyboard or screen-reader user: no `role="dialog"`, no Escape-to-close, and -
 * the most consequential gap - no focus management at all. Opening one left focus wherever it
 * already was, meaning Tab kept moving through the (still-interactive) page behind the
 * darkened overlay rather than into the dialog that visually has all the attention. A keyboard
 * user had no reliable way to even discover the dialog was there, let alone use only it while
 * it was open.
 *
 * Fixes: focus moves into the dialog on open and returns to whatever triggered it on close;
 * Tab/Shift+Tab cycle only among the dialog's own focusable elements while it's open (a manual
 * trap, not a browser-native one - no `<dialog>` element is used here, so nothing does this for
 * free); Escape closes it, matching every native dialog; `role="dialog"` + `aria-modal="true"` +
 * `aria-labelledby` pointing at the title let a screen reader announce it as a dialog with a
 * name, instead of as an unlabeled, ambiguous chunk of the page.
 */
export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  /** The finding-detail view (evidence JSON, remediation text) needs more room than the default max-w-md forms. */
  wide?: boolean;
}) {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
    return () => {
      previouslyFocused?.focus();
    };
  }, []);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const panel = panelRef.current;
      if (!panel) return;
      const focusables = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  return (
    <div
      className="animate-modal-backdrop fixed inset-0 z-50 flex items-center justify-center bg-void/80 px-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        className={`animate-modal-panel w-full ${wide ? "max-w-2xl" : "max-w-md"} max-h-[85vh] overflow-y-auto rounded-lg border border-neon-cyan/30 bg-panel p-5 shadow-[0_0_30px_rgba(0,240,255,0.1)] outline-none`}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 id={titleId} className="font-display text-lg font-bold text-neon-cyan">
            {title}
          </h2>
          <button
            onClick={onClose}
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-slate-700 font-mono text-sm text-slate-400 transition hover:border-neon-cyan/50 hover:bg-neon-cyan/10 hover:text-neon-cyan"
            aria-label="Close"
          >
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
