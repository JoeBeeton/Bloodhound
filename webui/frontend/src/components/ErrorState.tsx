/**
 * A failed query shouldn't be a dead end - every error state offers a retry, not just a static
 * message. role="alert" (not the more common role="status"): an accessibility review found this
 * component - used across ~20 pages for exactly this "a query/mutation just failed" moment - had
 * no aria-live announcement at all, so a screen-reader user watching a loading state got no
 * indication anything happened once it resolved to an error; they'd have to go hunting the page
 * for what changed. role="alert" (implicit aria-live="assertive") over role="status" specifically
 * because this is time-sensitive, action-relevant information (WAI-ARIA APG's own guidance calls
 * out "login attempt failure" as a canonical alert-role example) - the same urgency distinction
 * this codebase's CopyButton already draws for its own, deliberately calmer aria-live="polite"
 * copy-confirmation use case.
 */
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex items-center gap-3 rounded-lg border border-severity-critical/30 bg-severity-critical/5 px-4 py-3"
    >
      <p className="font-mono text-sm text-severity-critical">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="rounded border border-severity-critical/40 px-2.5 py-1 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10"
        >
          Try again
        </button>
      )}
    </div>
  );
}
