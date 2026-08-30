import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch, totalCountFromResponse } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import { usePageTitle } from "../lib/usePageTitle";

interface AuditLogEntry {
  id: string;
  actorUserId: string | null;
  actorEmail: string;
  action: string;
  targetType: string;
  targetId: string;
  detail: string | null;
  createdAt: string;
}

interface AuditLogPage {
  items: AuditLogEntry[];
  totalCount: number;
}

const PAGE_SIZE = 50;

async function fetchAuditLog(orgId: string, limit: number): Promise<AuditLogPage> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/audit-log?limit=${limit}&offset=0`);
  if (!res.ok) throw new Error("Failed to load the audit log.");
  const items: AuditLogEntry[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
}

const ACTION_LABELS: Record<string, string> = {
  USER_CREATED: "User created",
  USER_ROLE_OR_STATUS_CHANGED: "Role/status changed",
  USER_PASSWORD_RESET: "Password reset",
  TARGET_DELETED: "Target deleted",
  RULE_ENABLED: "Rule enabled",
  RULE_DISABLED: "Rule disabled",
};

const DESTRUCTIVE_ACTIONS = new Set(["TARGET_DELETED", "USER_PASSWORD_RESET", "RULE_DISABLED"]);

const TIMESTAMP_FORMAT = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

/**
 * Read-only history of the sensitive, org-scoped actions an admin can take - who changed a
 * user's role, who reset whose password, who deleted a target, who disabled a detection rule.
 * A product/AppSec review found none of this was recorded anywhere: every one of these actions
 * happened invisibly, with no way to answer "who did this and when" after the fact. Deliberately
 * covers the highest-value sensitive actions (identity/access changes, irreversible deletes,
 * detection-suppressing toggles) rather than every write in the system - see V43__audit_log.sql.
 */
export function AdminAuditLogPage() {
  usePageTitle("Audit Log");
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

  const query = useQuery({
    queryKey: ["admin-audit-log", orgId, visibleCount],
    queryFn: () => fetchAuditLog(orgId, visibleCount),
    enabled: !!orgId,
  });

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-2">
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
          <h1 className="font-display text-2xl font-bold text-neon-cyan">Audit log</h1>
        </div>
        <AdminSubNav />

        <p className="mb-4 font-mono text-xs text-slate-400">
          User role/status changes, password resets, target deletions, and detection-rule toggles for this
          organization.
        </p>

        {query.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
        {query.isError && <ErrorState message="Failed to load the audit log." onRetry={() => query.refetch()} />}

        {query.data && query.data.items.length === 0 && (
          <p className="font-mono text-sm text-slate-400">No audited actions yet.</p>
        )}

        {query.data && query.data.items.length > 0 && (
          // Four columns, two fixed-width, comfortably exceed a narrow viewport - lets this box
          // scroll horizontally on its own rather than the whole page (see AdminUsersPage for the
          // same fix and the live-confirmed overflow this closes).
          <div className="overflow-x-auto rounded-lg border border-neon-cyan/20 bg-panel/60">
            <div className="grid min-w-[640px] grid-cols-[150px_1fr_160px_1fr] gap-3 border-b border-neon-cyan/20 px-4 py-2 font-mono text-[11px] uppercase tracking-widest text-slate-400">
              <span>When</span>
              <span>Actor</span>
              <span>Action</span>
              <span>Detail</span>
            </div>
            {query.data.items.map((entry, i) => (
              <div
                key={entry.id}
                className={`grid min-w-[640px] grid-cols-[150px_1fr_160px_1fr] items-start gap-3 px-4 py-2.5 ${
                  i > 0 ? "border-t border-neon-cyan/10" : ""
                }`}
              >
                <span className="font-mono text-xs text-slate-400" title={entry.createdAt}>
                  {TIMESTAMP_FORMAT.format(new Date(entry.createdAt))}
                </span>
                <span className="truncate font-mono text-xs text-slate-300">{entry.actorEmail}</span>
                <span
                  className={`font-mono text-xs ${
                    DESTRUCTIVE_ACTIONS.has(entry.action) ? "text-severity-high" : "text-neon-cyan"
                  }`}
                >
                  {ACTION_LABELS[entry.action] ?? entry.action}
                </span>
                <span className="font-mono text-xs text-slate-400">{entry.detail ?? "—"}</span>
              </div>
            ))}
          </div>
        )}

        {query.data && query.data.items.length < query.data.totalCount && (
          <button
            onClick={() => setVisibleCount((c) => c + PAGE_SIZE)}
            className="mt-3 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:text-neon-cyan/70"
          >
            Load older ▾ ({query.data.totalCount - query.data.items.length} more)
          </button>
        )}
      </div>
    </Shell>
  );
}
