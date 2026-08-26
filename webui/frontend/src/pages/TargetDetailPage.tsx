import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AuthorizationPanel } from "../components/AuthorizationPanel";
import { BrandProtectionPanel } from "../components/BrandProtectionPanel";
import { CategoryBreakdown } from "../components/CategoryBreakdown";
import { ErrorState } from "../components/ErrorState";
import { FindingCard } from "../components/FindingCard";
import { FindingDetailModal } from "../components/FindingDetailModal";
import { FindingDiffView } from "../components/FindingDiffView";
import { FindingsFilterBar, type FindingsFilterState } from "../components/FindingsFilterBar";
import { GradeBadge } from "../components/GradeBadge";
import { TechHostingPanel } from "../components/TechHostingPanel";
import { ScanRunDrilldown } from "../components/ScanRunDrilldown";
import { ScoreTrendChart } from "../components/ScoreTrendChart";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { SCHEDULE_OPTIONS } from "../lib/schedule";
import type { Finding, FindingCategory, ScanRunDetail, Severity, ScoreSnapshot, Subdomain, Target } from "../lib/types";

async function updateSchedule(targetId: string, scanCadenceSeconds: number): Promise<Target> {
  const res = await apiFetch(`/api/v1/targets/${targetId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scanCadenceSeconds }),
  });
  if (!res.ok) throw new Error("Failed to update schedule.");
  return res.json();
}

async function fetchTarget(id: string): Promise<Target> {
  const res = await apiFetch(`/api/v1/targets/${id}`);
  if (!res.ok) throw new Error("Failed to load target.");
  return res.json();
}

async function fetchFindings(targetId: string, filters: FindingsFilterState): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (filters.severities.length > 0) params.set("severity", filters.severities.join(","));
  if (filters.categories.length > 0) params.set("category", filters.categories.join(","));
  const qs = params.toString();
  const res = await apiFetch(`/api/v1/targets/${targetId}/findings${qs ? `?${qs}` : ""}`);
  if (!res.ok) throw new Error("Failed to load findings.");
  return res.json();
}

async function triggerScan(targetId: string): Promise<{ id: string }> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/scan`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to start scan.");
  return res.json();
}

async function triggerDeepScan(targetId: string): Promise<{ id: string }> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/scan/deep`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to start deep scan.");
  return res.json();
}

async function fetchRun(runId: string): Promise<ScanRunDetail> {
  const res = await apiFetch(`/api/v1/runs/${runId}`);
  if (!res.ok) throw new Error("Failed to load scan run.");
  return res.json();
}

async function fetchSubdomains(targetId: string): Promise<Subdomain[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/subdomains`);
  if (!res.ok) throw new Error("Failed to load subdomains.");
  return res.json();
}

async function fetchScoreHistory(targetId: string): Promise<ScoreSnapshot[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/score/history`);
  if (!res.ok) throw new Error("Failed to load score history.");
  return res.json();
}

// A single target can legitimately carry hundreds of findings/subdomains
// (e.g. a large real domain's subdomain enumeration) - rendering all of them
// unbounded turns the page into a multi-thousand-pixel scroll (found via
// Milestone 9's real screenshot review: 24,800px tall against real data).
// Cap the initial render and let the analyst expand on demand.
const DISPLAY_CAP = 25;

// Mirrors ScanRunService's TIER1_SUBDOMAIN_CAP / TIER2_SUBDOMAIN_CAP on
// central-server - purely informational text here, the real caps are
// enforced server-side when building each scan's job payload.
const TIER1_SUBDOMAIN_CAP = 40;
const TIER2_SUBDOMAIN_CAP = 15;

function ShowMoreToggle({
  totalCount,
  expanded,
  onToggle,
}: {
  totalCount: number;
  expanded: boolean;
  onToggle: () => void;
}) {
  if (totalCount <= DISPLAY_CAP) return null;
  return (
    <button
      onClick={onToggle}
      className="mt-3 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:text-neon-cyan/70"
    >
      {expanded ? "Show fewer ▴" : `Show all ${totalCount} ▾`}
    </button>
  );
}

export function TargetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const targetId = id!;
  const queryClient = useQueryClient();

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

  const targetQuery = useQuery({ queryKey: ["target", targetId], queryFn: () => fetchTarget(targetId) });
  const findingsQuery = useQuery({
    queryKey: ["findings", targetId, filters],
    queryFn: () => fetchFindings(targetId, filters),
  });
  const subdomainsQuery = useQuery({ queryKey: ["subdomains", targetId], queryFn: () => fetchSubdomains(targetId) });
  const subdomainCount = subdomainsQuery.data?.length ?? 0;
  const scoreHistoryQuery = useQuery({
    queryKey: ["score-history", targetId],
    queryFn: () => fetchScoreHistory(targetId),
  });

  const [activeRunId, setActiveRunId] = useState<string | undefined>(undefined);
  const runQuery = useQuery({
    queryKey: ["run", activeRunId],
    queryFn: () => fetchRun(activeRunId!),
    enabled: !!activeRunId,
    refetchInterval: (query) => (query.state.data?.status === "RUNNING" ? 2000 : false),
  });

  const scanNow = useMutation({
    mutationFn: () => triggerScan(targetId),
    onSuccess: (run) => setActiveRunId(run.id),
  });

  const deepScanNow = useMutation({
    mutationFn: () => triggerDeepScan(targetId),
    onSuccess: (run) => setActiveRunId(run.id),
  });

  const updateScheduleMutation = useMutation({
    mutationFn: (scanCadenceSeconds: number) => updateSchedule(targetId, scanCadenceSeconds),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["target", targetId] }),
  });

  // Once a run completes, findings/subdomains/score are all stale - refresh them.
  useEffect(() => {
    if (runQuery.data?.status && runQuery.data.status !== "RUNNING" && activeRunId === runQuery.data.id) {
      queryClient.invalidateQueries({ queryKey: ["findings", targetId] });
      queryClient.invalidateQueries({ queryKey: ["subdomains", targetId] });
      queryClient.invalidateQueries({ queryKey: ["score-history", targetId] });
      queryClient.invalidateQueries({ queryKey: ["target", targetId] });
      queryClient.invalidateQueries({ queryKey: ["diff", targetId] });
    }
  }, [runQuery.data?.status, runQuery.data?.id, activeRunId, targetId, queryClient]);

  const status = runQuery.data?.status;
  const target = targetQuery.data;

  const [findingsExpanded, setFindingsExpanded] = useState(false);
  const [sortByScoreImpact, setSortByScoreImpact] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  // Server-ordered by severity by default; "sort by score impact" answers the
  // actual question this feature exists for - "what should I fix first for the
  // biggest score improvement" - findings that don't affect the score (null/NaN
  // delta) sink to the bottom rather than interleaving confusingly with real deltas.
  const sortedFindings = sortByScoreImpact
    ? findingsQuery.data
        ?.slice()
        .sort((a, b) => (b.scoreImpact?.overallScoreDelta ?? -1) - (a.scoreImpact?.overallScoreDelta ?? -1))
    : findingsQuery.data;
  const visibleFindings = findingsExpanded ? sortedFindings : sortedFindings?.slice(0, DISPLAY_CAP);

  return (
    <Shell>
      <div className="w-full max-w-3xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Target</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">{target?.hostname ?? "…"}</h1>
            {target && (
              <div className="mt-1 flex items-center gap-3">
                <p className="font-mono text-xs uppercase tracking-widest text-slate-400">
                  {target.targetType} · {target.isActive ? "active" : "paused"}
                </p>
                <GradeBadge grade={target.grade} score={target.overallScore} />
                {target.tier1OverallScore !== null && (
                  <span className="flex items-center gap-1 opacity-70" title="Tier 1 only — excludes findings from authorized deep scans, which only run on this domain and not on competitors. This is the score used for fair /compare comparisons.">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500">fair:</span>
                    <GradeBadge grade={target.tier1Grade} score={target.tier1OverallScore} />
                  </span>
                )}
              </div>
            )}
          </div>
          <Link to="/targets" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
            ← Targets
          </Link>
        </div>

        <div className="mb-8 flex flex-col gap-3 rounded-lg border border-neon-cyan/20 bg-panel/80 p-4">
          <div className="flex items-center gap-4">
            {status && (
              <span
                className={`font-mono text-xs uppercase tracking-widest ${
                  status === "RUNNING"
                    ? "animate-pulse text-neon-amber"
                    : status === "COMPLETE"
                      ? "text-neon-cyan"
                      : "text-severity-critical"
                }`}
              >
                {status.replace("_", " ")}
              </span>
            )}
            <span
              title={`Scans ${target?.hostname ?? "the root domain"} plus ${Math.min(
                subdomainCount,
                TIER1_SUBDOMAIN_CAP,
              )} known subdomain(s)${subdomainCount > TIER1_SUBDOMAIN_CAP ? ` (of ${subdomainCount} discovered)` : ""}.`}
            >
              <button
                onClick={() => scanNow.mutate()}
                disabled={scanNow.isPending || status === "RUNNING"}
                className="rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10 disabled:opacity-40"
              >
                {status === "RUNNING" ? "Scanning…" : "Scan now"}
              </button>
            </span>
            <span
              title={
                target?.authorizationStatus !== "AUTHORIZED"
                  ? "Authorize this target below before running a Tier 2 deep scan."
                  : `Deep-scans ${target?.hostname ?? "the root domain"} plus up to ${Math.min(
                      subdomainCount,
                      TIER2_SUBDOMAIN_CAP,
                    )} of ${subdomainCount} known subdomain(s), sequentially, within an overall time budget.`
              }
            >
              <button
                onClick={() => deepScanNow.mutate()}
                disabled={deepScanNow.isPending || status === "RUNNING" || target?.authorizationStatus !== "AUTHORIZED"}
                className="rounded border border-neon-amber/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-amber transition hover:bg-neon-amber/10 disabled:opacity-30"
              >
                {status === "RUNNING" ? "Scanning…" : "Deep scan (Tier 2)"}
              </button>
            </span>
          </div>
          <p className="font-mono text-xs text-slate-400">
            Scans cover {target?.hostname ?? "the root domain"} and up to {TIER1_SUBDOMAIN_CAP} known subdomains
            (deep scans: up to {TIER2_SUBDOMAIN_CAP}, scanned sequentially within a time budget)
            {subdomainCount > 0 ? ` — ${subdomainCount} currently discovered.` : "."}
          </p>
          {runQuery.data && status !== "RUNNING" && <ScanRunDrilldown run={runQuery.data} />}
        </div>

        {target && (
          <div className="mb-8 flex flex-wrap items-center gap-3 rounded-lg border border-neon-cyan/10 bg-panel/60 px-4 py-3">
            <label className="font-mono text-xs uppercase tracking-widest text-slate-400">Scan schedule</label>
            <select
              value={target.scanCadenceSeconds}
              disabled={updateScheduleMutation.isPending}
              onChange={(e) => updateScheduleMutation.mutate(Number(e.target.value))}
              className="rounded border border-slate-700 bg-void px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-neon-cyan disabled:opacity-40"
            >
              {SCHEDULE_OPTIONS.map((opt) => (
                <option key={opt.seconds} value={opt.seconds}>
                  {opt.label}
                </option>
              ))}
            </select>
            <span className="font-mono text-xs text-slate-500">
              Next scheduled scan: {new Date(target.nextScanAt).toLocaleString()}
            </span>
          </div>
        )}

        <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-400">Tier 2 authorization</h2>
        <div className="mb-10">
          <AuthorizationPanel targetId={targetId} />
        </div>

        <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-400">Security posture</h2>
        <div className="mb-10 grid gap-4 sm:grid-cols-2">
          <CategoryBreakdown categoryScores={scoreHistoryQuery.data?.at(-1)?.categoryScores} />
          <ScoreTrendChart history={scoreHistoryQuery.data} />
        </div>

        <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-400">Technology &amp; hosting</h2>
        <div className="mb-10">
          <TechHostingPanel targetId={targetId} rootHostname={target?.hostname} />
        </div>

        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="font-mono text-sm uppercase tracking-widest text-slate-400">
            Open findings {findingsQuery.data ? `(${findingsQuery.data.length})` : ""}
          </h2>
          {findingsQuery.data && findingsQuery.data.length > 1 && (
            <button
              onClick={() => setSortByScoreImpact((v) => !v)}
              className="font-mono text-[10px] uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan"
            >
              Sort: {sortByScoreImpact ? "Score impact ▾" : "Severity ▾"}
            </button>
          )}
        </div>

        <FindingsFilterBar value={filters} onChange={setFilters} resultCount={findingsQuery.data?.length} />

        {findingsQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading findings…</p>}
        {findingsQuery.isError && (
          <ErrorState message="Failed to load findings." onRetry={() => findingsQuery.refetch()} />
        )}
        {findingsQuery.data?.length === 0 && (
          <p className="font-mono text-sm text-slate-400">
            {filters.severities.length > 0 || filters.categories.length > 0
              ? "No findings match the selected filters."
              : "No open findings — run a scan to check this target."}
          </p>
        )}

        <div className="flex flex-col gap-3">
          {visibleFindings?.map((finding) => (
            <FindingCard key={finding.id} finding={finding} onSelect={() => setSelectedFinding(finding)} />
          ))}
        </div>
        {findingsQuery.data && (
          <ShowMoreToggle
            totalCount={findingsQuery.data.length}
            expanded={findingsExpanded}
            onToggle={() => setFindingsExpanded((v) => !v)}
          />
        )}

        <h2 className="mb-3 mt-10 font-mono text-sm uppercase tracking-widest text-slate-400">Brand protection</h2>
        <div className="mb-10">
          <BrandProtectionPanel targetId={targetId} />
        </div>

        <div className="mt-10 flex items-center justify-between gap-3 rounded-lg border border-neon-cyan/20 bg-panel/60 p-4">
          <div>
            <h2 className="font-mono text-sm uppercase tracking-widest text-slate-400">
              Subdomains {subdomainsQuery.data ? `(${subdomainsQuery.data.length})` : ""}
            </h2>
            <p className="mt-1 font-mono text-xs text-slate-500">
              Full list with fingerprint data and per-subdomain findings.
            </p>
          </div>
          <Link
            to={`/targets/${targetId}/subdomains`}
            className="shrink-0 rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10"
          >
            View subdomains →
          </Link>
        </div>

        <h2 className="mb-3 mt-10 font-mono text-sm uppercase tracking-widest text-slate-400">
          Compare with previous scan
        </h2>
        <FindingDiffView targetId={targetId} runId={scoreHistoryQuery.data?.at(-1)?.scanRunId} />
      </div>
      {selectedFinding && <FindingDetailModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </Shell>
  );
}
