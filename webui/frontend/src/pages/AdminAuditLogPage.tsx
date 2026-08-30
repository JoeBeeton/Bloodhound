import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
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

function auditLogFilterParams(actorEmail: string, action: string | null): URLSearchParams {
  const params = new URLSearchParams();
  if (actorEmail) params.set("actorEmail", actorEmail);
  if (action) params.set("action", action);
  return params;
}

async function fetchAuditLog(orgId: string, actorEmail: string, action: string | null, limit: number): Promise<AuditLogPage> {
  const params = new URLSearchParams({ limit: String(limit), offset: "0" });
  const filterParams = auditLogFilterParams(actorEmail, action);
  filterParams.forEach((value, key) => params.set(key, value));
  const res = await apiFetch(`/api/v1/orgs/${orgId}/audit-log?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load the audit log.");
  const items: AuditLogEntry[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
}

/**
 * Same blob-and-synthetic-object-URL pattern as FindingsPage's downloadOrgFindingsCsv - a plain
 * `<a href>` can't carry the bearer token the export endpoint requires. Respects whatever
 * actorEmail/action filter is currently applied, same convention as the findings exports.
 */
async function downloadAuditLogCsv(orgId: string, actorEmail: string, action: string | null): Promise<void> {
  const params = auditLogFilterParams(actorEmail, action);
  const res = await apiFetch(`/api/v1/orgs/${orgId}/audit-log/export?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to export the audit log.");
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const filenameMatch = disposition.match(/filename="([^"]+)"/);
  const filename = filenameMatch ? filenameMatch[1] : "audit-log.csv";

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

const ACTION_LABELS: Record<string, string> = {
  USER_CREATED: "User created",
  USER_ROLE_OR_STATUS_CHANGED: "Role/status changed",
  USER_PASSWORD_RESET: "Password reset",
  TARGET_DELETED: "Target deleted",
  TARGET_REMOVED: "Target removed",
  TARGET_RESTORED: "Target restored",
  RULE_ENABLED: "Rule enabled",
  RULE_DISABLED: "Rule disabled",
  SLACK_INTEGRATION_SAVED: "Slack integration saved",
  SLACK_INTEGRATION_REMOVED: "Slack integration removed",
  MCP_ENABLED: "MCP access enabled",
  MCP_DISABLED: "MCP access disabled",
  SCIM_TOKEN_CREATED: "SCIM token created",
  SCIM_TOKEN_REVOKED: "SCIM token revoked",
};

const ACTION_VALUES = Object.keys(ACTION_LABELS);

const DESTRUCTIVE_ACTIONS = new Set([
  "TARGET_DELETED",
  "USER_PASSWORD_RESET",
  "RULE_DISABLED",
  "SLACK_INTEGRATION_REMOVED",
  "MCP_DISABLED",
  "SCIM_TOKEN_REVOKED",
]);

const TIMESTAMP_FORMAT = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

const INACTIVE_TOGGLE = "border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-200";

/**
 * Read-only history of the sensitive, org-scoped actions an admin can take - who changed a
 * user's role, who reset whose password, who deleted a target, who disabled a detection rule.
 * A product/AppSec review found none of this was recorded anywhere: every one of these actions
 * happened invisibly, with no way to answer "who did this and when" after the fact. Deliberately
 * covers the highest-value sensitive actions (identity/access changes, irreversible deletes,
 * detection-suppressing toggles) rather than every write in the system - see V43__audit_log.sql.
 *
 * Filtering by actor and action was added after the page had been live a while - once an org
 * accumulates more than a screenful of history, "what did this admin do" or "show me every
 * password reset" was only answerable by paging through everything chronologically. Both filters
 * are server-side (see AuditLogRepository#findByOrganization) so they narrow the full history,
 * not just whatever page happens to be loaded.
 */
export function AdminAuditLogPage() {
  usePageTitle("Audit Log");
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [actorSearch, setActorSearch] = useState("");
  const [action, setAction] = useState<string | null>(null);

  // Debounced so typing an email/name doesn't fire a request per keystroke - same pattern as
  // SubdomainsPage's hostname filter, since this is a real server round trip each time it changes.
  const [debouncedActorSearch, setDebouncedActorSearch] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedActorSearch(actorSearch), 300);
    return () => clearTimeout(timer);
  }, [actorSearch]);

  const query = useQuery({
    queryKey: ["admin-audit-log", orgId, debouncedActorSearch, action, visibleCount],
    queryFn: () => fetchAuditLog(orgId, debouncedActorSearch, action, visibleCount),
    enabled: !!orgId,
  });

  const exportCsvMutation = useMutation({
    mutationFn: () => downloadAuditLogCsv(orgId, debouncedActorSearch, action),
  });

  const hasFilters = actorSearch.length > 0 || action !== null;

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-2 flex items-start justify-between gap-3">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">Audit log</h1>
          </div>
          {query.data && query.data.totalCount > 0 && (
            <button
              onClick={() => exportCsvMutation.mutate()}
              disabled={exportCsvMutation.isPending}
              className="font-mono text-[10px] uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan disabled:opacity-50"
              title="Export the currently filtered audit log as CSV"
            >
              {exportCsvMutation.isPending ? "Exporting…" : "Export CSV ↓"}
            </button>
          )}
        </div>
        <AdminSubNav />

        <p className="mb-4 font-mono text-xs text-slate-400">
          User role/status changes, password resets, target deletions, and detection-rule toggles for this
          organization.
        </p>
        {exportCsvMutation.isError && (
          <p className="mb-2 font-mono text-xs text-severity-critical">Failed to export the audit log. Try again.</p>
        )}

        <div className="mb-4 flex flex-col gap-2 rounded-lg border border-neon-cyan/10 bg-panel/40 p-3">
          <div className="flex items-center gap-2">
            <label htmlFor="audit-actor-search" className="sr-only">
              Filter by actor email
            </label>
            <input
              id="audit-actor-search"
              value={actorSearch}
              onChange={(e) => {
                setActorSearch(e.target.value);
                setVisibleCount(PAGE_SIZE);
              }}
              placeholder="Filter by actor email…"
              className="w-full max-w-xs rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none placeholder:text-muted focus:border-neon-cyan"
            />
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-slate-500">Action</span>
            {ACTION_VALUES.map((value) => {
              const active = action === value;
              return (
                <button
                  key={value}
                  aria-pressed={active}
                  onClick={() => {
                    setAction(active ? null : value);
                    setVisibleCount(PAGE_SIZE);
                  }}
                  className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest transition ${
                    active ? "border-neon-cyan bg-neon-cyan/15 text-neon-cyan" : INACTIVE_TOGGLE
                  }`}
                >
                  {ACTION_LABELS[value]}
                </button>
              );
            })}
          </div>
          <div className="flex items-center justify-between gap-3 border-t border-neon-cyan/10 pt-2">
            <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500">
              {query.data === undefined ? "…" : `${query.data.totalCount} result${query.data.totalCount === 1 ? "" : "s"}`}
            </span>
            {hasFilters && (
              <button
                onClick={() => {
                  setActorSearch("");
                  setAction(null);
                  setVisibleCount(PAGE_SIZE);
                }}
                className="font-mono text-[10px] uppercase tracking-widest text-neon-magenta transition hover:text-neon-magenta/70"
              >
                Clear filters ✕
              </button>
            )}
          </div>
        </div>

        {query.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
        {query.isError && <ErrorState message="Failed to load the audit log." onRetry={() => query.refetch()} />}

        {query.data && query.data.items.length === 0 && (
          <p className="font-mono text-sm text-slate-400">
            {hasFilters ? "No audited actions match the selected filters." : "No audited actions yet."}
          </p>
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
