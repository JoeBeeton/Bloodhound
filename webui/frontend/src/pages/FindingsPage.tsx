import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
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

async function fetchOrgFindings(filters: FindingsFilterState, limit: number): Promise<FindingsPageData> {
  const params = new URLSearchParams({ limit: String(limit), offset: "0" });
  if (filters.severities.length > 0) params.set("severity", filters.severities.join(","));
  if (filters.categories.length > 0) params.set("category", filters.categories.join(","));
  const res = await apiFetch(`/api/v1/findings?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load findings.");
  const items: OrgFinding[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
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
  };
  const setFilters = (next: FindingsFilterState) => {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        next.severities.length > 0 ? params.set("severity", next.severities.join(",")) : params.delete("severity");
        next.categories.length > 0 ? params.set("category", next.categories.join(",")) : params.delete("category");
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

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-2">
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Org-wide</p>
          <h1 className="font-display text-2xl font-bold text-neon-cyan">Findings</h1>
        </div>

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
            {filters.severities.length > 0 || filters.categories.length > 0
              ? "No open findings match the selected filters."
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
                  <span className="font-mono text-[10px] uppercase tracking-widest text-slate-400">{f.targetHostname}</span>
                </div>
                <p className="font-mono text-sm text-slate-200">{f.title}</p>
                <div className="mt-1 flex items-center justify-between gap-2">
                  <span className="font-mono text-[10px] text-slate-600">{f.displayId}</span>
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
