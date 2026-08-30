import { useState } from "react";

const COPIED_LABEL_MS = 1500;

/** Shared "Copy" button for the one-time-reveal secrets (temp password, API key, SCIM bearer
 * token) - all three call sites used to fire navigator.clipboard.writeText with zero visual
 * feedback, leaving whether the click actually worked to guesswork. Flips to "Copied ✓" for
 * 1.5s so the click has a visible result, same as every other confirmed action in the app. */
export function CopyButton({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  async function handleClick() {
    try {
      await navigator.clipboard?.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), COPIED_LABEL_MS);
    } catch {
      // Clipboard access can fail (permissions, insecure context) - silently no-op rather than
      // throw, same as the bare navigator.clipboard?.writeText() calls this replaces did.
    }
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      className={className ?? "shrink-0 font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan"}
    >
      {/* aria-live on a span that's always present (not conditionally mounted) - a screen reader
       * only announces a live region's content changing if the region itself already existed
       * before the mutation, so swapping the whole element in/out on `copied` wouldn't announce
       * anything. Sighted users got the visible confirmation this same review found CopyButton
       * added for in the first place; a screen reader user clicking "Copy" had no way to know it
       * worked short of trusting the clipboard silently. */}
      <span aria-live="polite">{copied ? <span className="text-neon-cyan">Copied ✓</span> : "Copy"}</span>
    </button>
  );
}
