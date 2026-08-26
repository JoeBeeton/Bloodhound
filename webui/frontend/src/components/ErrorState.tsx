/** A failed query shouldn't be a dead end - every error state offers a retry, not just a static message. */
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-severity-critical/30 bg-severity-critical/5 px-4 py-3">
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
