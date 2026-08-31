import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { FindingDetailModal } from "../components/FindingDetailModal";
import { FindingsFilterBar, type FindingsFilterState } from "../components/FindingsFilterBar";
import { ScoreImpactBadge } from "../components/ScoreImpactBadge";
import { Shell } from "../components/Shell";
import { apiFetch, totalCountFromResponse } from "../lib/apiClient";
import type { FindingCategory, OrgFinding, Severity } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

interface FindingsPageData {
  items: OrgFinding[];
  totalCount: number;
}

const PAGE_SIZE = 50;

/** Same bug class the params-writer above documents - reads the raw URL value back, defaulting to OPEN for anything unrecognized (a stale/hand-edited URL, not just an absent param). */
export function parseStatusParam(value: string | null): FindingsFilterState["status"] {
  return value === "RESOLVED" || value === "DISMISSED" ? value : "OPEN";
}

export function orgFindingsFilterParams(filters: FindingsFilterState): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.severities.length > 0) params.set("severity", filters.severities.join(","));
  if (filters.categories.length > 0) params.set("category", filters.categories.join(","));
  // OPEN is the server's own default (FindingRepository#appendFilters) - only a non-default
  // value needs to be sent at all. A bug found live after FindingsFilterBar gained its third
  // "Dismissed" toggle: this only ever forwarded the literal string "RESOLVED", so clicking
  // Dismissed rendered as pressed/active but silently kept showing Open findings - the param was
  // deleted, not set, for any status other than exactly "RESOLVED".
  if (filters.status && filters.status !== "OPEN") params.set("status", filters.status);
  if (filters.search) params.set("search", filters.search);
  return params;
}

async function fetchOrgFindings(filters: FindingsFilterState, limit: number): Promise<FindingsPageData> {
  const params = orgFindingsFilterParams(filters);
  params.set("limit", String(limit));
  params.set("offset", "0");
  const res = await apiFetch(`/api/v1/findings?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load findings.");
  const items: OrgFinding[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
}

/**
 * A plain `<a href>` can't carry the bearer token the export endpoint requires - same
 * constraint TargetDetailPage's own downloadFindingsCsv (and ScreenshotThumbnail before it) hit,
 * fetches the CSV as a blob and drives the download through a synthetic, immediately-revoked
 * object URL instead. Respects the currently-applied filters, same as the target-scoped export.
 */
async function downloadOrgFindingsCsv(filters: FindingsFilterState): Promise<void> {
  const params = orgFindingsFilterParams(filters);
  const res = await apiFetch(`/api/v1/findings/export?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to export findings.");
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const filenameMatch = disposition.match(/filename="([^"]+)"/);
  const filename = filenameMatch ? filenameMatch[1] : "findings.csv";

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "text-severity-critical",
  HIGH: "text-severity-high",
  MEDIUM: "text-severity-medium",
  LOW: "text-severity-low",
  INFO: "text-severity-info",
};

const SEVERITY_ACCENT: Record<Severity, string> = {
  CRITICAL: "border-l-severity-critical",
  HIGH: "border-l-severity-high",
  MEDIUM: "border-l-severity-medium",
  LOW: "border-l-severity-low",
  INFO: "border-l-severity-info",
};

/**
 * Every open finding across every target in the org, filterable and paginated - previously the
 * only ways to see findings were one target at a time, or the dashboard's un-paginated top 10
 * (Critical/High only). A product review found no page like this existed at all, despite the
 * backing endpoint (GET /api/v1/findings) already existing as part of the documented read-only
 * external API - the in-app UI just never had a screen that called it.
 */
export function FindingsPage() {
  usePageTitle("Findings");
  const [searchParams, setSearchParams] = useSearchParams();
  const filters: FindingsFilterState = {
    severities: (searchParams.get("severity")?.split(",").filter(Boolean) ?? []) as Severity[],
    categories: (searchParams.get("category")?.split(",").filter(Boolean) ?? []) as FindingCategory[],
    status: parseStatusParam(searchParams.get("status")),
    search: searchParams.get("search") ?? undefined,
  };
  const setFilters = (next: FindingsFilterState) => {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        next.severities.length > 0 ? params.set("severity", next.severities.join(",")) : params.delete("severity");
        next.categories.length > 0 ? params.set("category", next.categories.join(",")) : params.delete("category");
        next.status && next.status !== "OPEN" ? params.set("status", next.status) : params.delete("status");
        next.search ? params.set("search", next.search) : params.delete("search");
        return params;
      },
      { replace: true },
    );
  };

  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [selectedFinding, setSelectedFinding] = useState<OrgFinding | null>(null);

  const query = useQuery({
    queryKey: ["org-findings", filters, visibleCount],
    queryFn: () => fetchOrgFindings(filters, visibleCount),
  });

  const exportCsvMutation = useMutation({
    mutationFn: () => downloadOrgFindingsCsv(filters),
  });

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-2 flex items-center justify-between gap-3">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Org-wide</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">Findings</h1>
          </div>
          {query.data && query.data.totalCount > 0 && (
            <button
              onClick={() => exportCsvMutation.mutate()}
              disabled={exportCsvMutation.isPending}
              className="font-mono text-[10px] uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan disabled:opacity-50"
              title="Export the currently filtered findings as CSV"
            >
              {exportCsvMutation.isPending ? "Exporting…" : "Export CSV ↓"}
            </button>
          )}
        </div>
        {exportCsvMutation.isError && (
          <p role="alert" className="mb-2 font-mono text-xs text-severity-critical">
            Failed to export findings. Try again.
          </p>
        )}

        <FindingsFilterBar
          value={filters}
          onChange={(next) => {
            setFilters(next);
            setVisibleCount(PAGE_SIZE);
          }}
          resultCount={query.data?.totalCount}
        />

        {query.isLoading && <p className="font-mono text-sm text-slate-400">Loading findings…</p>}
        {query.isError && <ErrorState message="Failed to load findings." onRetry={() => query.refetch()} />}
        {query.data?.totalCount === 0 && (
          <p className="rounded-lg border border-neon-cyan/10 bg-panel/40 p-4 font-mono text-sm text-neon-cyan">
            {filters.severities.length > 0 || filters.categories.length > 0 || filters.search
              ? `No ${(filters.status ?? "OPEN").toLowerCase()} findings match the selected filters.`
              : filters.status === "RESOLVED"
                ? "Nothing resolved yet."
                : filters.status === "DISMISSED"
                  ? "Nothing dismissed yet."
                  : "Clean sweep — no open findings across your organization."}
          </p>
        )}

        {query.data && query.data.items.length > 0 && (
          <div className="flex flex-col gap-2">
            {query.data.items.map((f) => (
              <button
                key={f.id}
                onClick={() => setSelectedFinding(f)}
                className={`block w-full rounded-lg border border-l-4 bg-panel/60 p-3 text-left transition hover:bg-panel border-neon-cyan/10 ${SEVERITY_ACCENT[f.severity]}`}
              >
                <div className="mb-1 flex items-center justify-between gap-3">
                  <span className={`font-mono text-[10px] font-bold uppercase tracking-widest ${SEVERITY_STYLES[f.severity]}`}>
                    {f.severity} · {f.category}
                  </span>
                  <div className="flex items-center gap-2">
                    {f.status === "RESOLVED" && (
                      <span className="rounded border border-neon-cyan/40 px-1 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-neon-cyan">
                        Resolved
                      </span>
                    )}
                    {f.status === "DISMISSED" && (
                      <span className="rounded border border-slate-600 px-1 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-slate-400">
                        Dismissed
                      </span>
                    )}
                    <span className="font-mono text-[10px] uppercase tracking-widest text-slate-400">{f.targetHostname}</span>
                  </div>
                </div>
                <p className="font-mono text-sm text-slate-200">{f.title}</p>
                <div className="mt-1 flex items-center justify-between gap-2">
                  <span className="font-mono text-[10px] text-muted">{f.displayId}</span>
                  <ScoreImpactBadge impact={f.scoreImpact} />
                </div>
              </button>
            ))}
          </div>
        )}

        {query.data && query.data.items.length < query.data.totalCount && (
          <button
            onClick={() => setVisibleCount((c) => c + PAGE_SIZE)}
            className="mt-3 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:text-neon-cyan/70"
          >
            Load more ▾ ({query.data.totalCount - query.data.items.length} more)
          </button>
        )}
      </div>
      {selectedFinding && <FindingDetailModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </Shell>
  );
}
