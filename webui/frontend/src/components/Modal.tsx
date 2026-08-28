import type { ReactNode } from "react";

/** A simple centered overlay dialog - shared by the remove-target confirmation, add-user, change-password, and finding-detail flows. */
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
  return (
    <div
      className="animate-modal-backdrop fixed inset-0 z-50 flex items-center justify-center bg-void/80 px-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className={`animate-modal-panel w-full ${wide ? "max-w-2xl" : "max-w-md"} max-h-[85vh] overflow-y-auto rounded-lg border border-neon-cyan/30 bg-panel p-5 shadow-[0_0_30px_rgba(0,240,255,0.1)]`}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="font-display text-lg font-bold text-neon-cyan">{title}</h2>
          <button
            onClick={onClose}
            className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan"
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
