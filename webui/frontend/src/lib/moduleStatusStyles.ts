/** Shared job-status pill styling - originally only on ScansPage, now also used by
 * JobQueuePanel (Attack Surface Map) since both render the exact same scan_jobs.status
 * values and should read as the same visual language rather than drifting apart. */
export const MODULE_STATUS_STYLES: Record<string, string> = {
  PENDING: "bg-slate-700 text-slate-400",
  CLAIMED: "bg-neon-amber/20 text-neon-amber",
  RUNNING: "bg-neon-amber/20 text-neon-amber animate-pulse",
  COMPLETE: "bg-neon-cyan/20 text-neon-cyan",
  FAILED: "bg-severity-critical/20 text-severity-critical",
  // A cancelled run drops out of the active-scans list within one poll cycle, so this is a
  // narrow window - added anyway since an undefined entry falls back to this exact same
  // style PENDING gets, same as every other status-style map in this codebase.
  CANCELLED: "bg-slate-800 text-muted",
  // Deliberately NOT the FAILED red - a confirmed-dead host is a correct scan outcome, not a
  // bug (see HostUnreachableException), and the run itself now reports COMPLETE rather than
  // PARTIAL_FAILURE when every other job succeeded. Neutral/muted, same family as PENDING.
  UNREACHABLE: "bg-slate-700 text-slate-400",
};
