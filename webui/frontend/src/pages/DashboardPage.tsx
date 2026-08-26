import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { FindingDetailModal } from "../components/FindingDetailModal";
import { GradeBadge } from "../components/GradeBadge";
import { ScoreImpactBadge } from "../components/ScoreImpactBadge";
import { ScoreTrendChart } from "../components/ScoreTrendChart";
import { Shell } from "../components/Shell";
import { StatTile } from "../components/StatTile";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import type { DashboardSummary, OrgFinding, ScoreSnapshot, Severity } from "../lib/types";

async function fetchDashboard(): Promise<DashboardSummary> {
  const res = await apiFetch("/api/v1/dashboard");
  if (!res.ok) throw new Error("Failed to load dashboard.");
  return res.json();
}

async function fetchScoreHistory(targetId: string): Promise<ScoreSnapshot[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/score/history`);
  if (!res.ok) throw new Error("Failed to load score history.");
  return res.json();
}

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "border-severity-critical/50 text-severity-critical",
  HIGH: "border-severity-high/50 text-severity-high",
  MEDIUM: "border-severity-medium/50 text-severity-medium",
  LOW: "border-severity-low/50 text-severity-low",
  INFO: "border-severity-info/50 text-severity-info",
};

const RUN_STATUS_STYLES: Record<string, string> = {
  RUNNING: "text-neon-amber animate-pulse",
  COMPLETE: "text-neon-cyan",
  PARTIAL_FAILURE: "text-severity-critical",
  FAILED: "text-severity-critical",
};

export function DashboardPage() {
  const { user } = useAuth();
  const dashboardQuery = useQuery({ queryKey: ["dashboard"], queryFn: fetchDashboard });
  const dashboard = dashboardQuery.data;
  const [selectedFinding, setSelectedFinding] = useState<OrgFinding | null>(null);

  return (
    <Shell>
      <div className="flex w-full max-w-5xl flex-col gap-10 text-left">
        <div>
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Org overview</p>
          <h1 className="font-display text-3xl font-bold text-neon-cyan">Welcome back, {user?.displayName}</h1>
        </div>

        {dashboardQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading dashboard…</p>}
        {dashboardQuery.isError && (
          <ErrorState message="Failed to load dashboard." onRetry={() => dashboardQuery.refetch()} />
        )}

        {dashboard && (
          <>
            {/* Stat tiles: totals at a glance */}
            <div className="flex flex-wrap gap-3">
              <StatTile label="Targets tracked" value={dashboard.stats.totalTargets} />
              <StatTile label="Own domains" value={dashboard.stats.ownCount} accent="text-neon-cyan" />
              <StatTile label="Competitors" value={dashboard.stats.competitorCount} accent="text-neon-magenta" />
              <StatTile label="Watchlist" value={dashboard.stats.watchlistCount} accent="text-neon-amber" />
              <StatTile
                label="Open critical"
                value={dashboard.stats.openCriticalCount}
                accent={dashboard.stats.openCriticalCount > 0 ? "text-severity-critical" : "text-slate-100"}
              />
              <StatTile
                label="Open high"
                value={dashboard.stats.openHighCount}
                accent={dashboard.stats.openHighCount > 0 ? "text-severity-high" : "text-slate-100"}
              />
            </div>

            {/* Hero: own domain(s) score + trend */}
            <section>
              <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-400">Your attack surface</h2>
              {dashboard.ownTargets.length === 0 ? (
                <div className="rounded-lg border border-neon-cyan/20 bg-panel/60 p-6 text-center">
                  <p className="mb-3 font-mono text-sm text-slate-400">
                    No domains of your own are being tracked yet.
                  </p>
                  <Link
                    to="/targets"
                    className="inline-block rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta"
                  >
                    Add your first domain
                  </Link>
                </div>
              ) : (
                <div className="grid gap-4 sm:grid-cols-2">
                  {dashboard.ownTargets.map((target) => (
                    <OwnTargetHeroCard key={target.id} targetId={target.id} hostname={target.hostname} />
                  ))}
                </div>
              )}
            </section>

            <div className="grid gap-8 lg:grid-cols-2">
              {/* Top open findings across the org */}
              <section>
                <div className="mb-3 flex items-center justify-between">
                  <h2 className="font-mono text-sm uppercase tracking-widest text-slate-400">
                    Top open findings ({dashboard.stats.openCriticalCount + dashboard.stats.openHighCount})
                  </h2>
                  <Link to="/targets" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
                    View all targets →
                  </Link>
                </div>
                {dashboard.topFindings.length === 0 ? (
                  <p className="rounded-lg border border-neon-cyan/10 bg-panel/40 p-4 font-mono text-sm text-neon-cyan">
                    Clean sweep — no open Critical or High findings across your organization.
                  </p>
                ) : (
                  <div className="flex flex-col gap-2">
                    {dashboard.topFindings.map((f) => (
                      <button
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`block w-full rounded-lg border bg-panel/60 p-3 text-left transition hover:bg-panel ${SEVERITY_STYLES[f.severity]}`}
                      >
                        <div className="mb-1 flex items-center justify-between gap-3">
                          <span className={`font-mono text-[10px] font-bold uppercase tracking-widest ${SEVERITY_STYLES[f.severity]}`}>
                            {f.severity} · {f.category}
                          </span>
                          <span className="font-mono text-[10px] uppercase tracking-widest text-slate-400">
                            {f.targetHostname}
                          </span>
                        </div>
                        <p className="font-mono text-sm text-slate-200">{f.title}</p>
                        <div className="mt-1">
                          <ScoreImpactBadge impact={f.scoreImpact} />
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </section>

              {/* Recent scan activity */}
              <section>
                <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-400">Recent scan activity</h2>
                {dashboard.recentActivity.length === 0 ? (
                  <p className="rounded-lg border border-neon-cyan/10 bg-panel/40 p-4 font-mono text-sm text-slate-400">
                    No scans have run yet.
                  </p>
                ) : (
                  <div className="overflow-hidden rounded-lg border border-neon-cyan/20 bg-panel/60">
                    {dashboard.recentActivity.map((run, i) => (
                      <Link
                        key={run.id}
                        to={`/scans/${run.id}`}
                        className={`flex items-center justify-between px-4 py-2.5 transition hover:bg-panel ${
                          i > 0 ? "border-t border-neon-cyan/10" : ""
                        }`}
                      >
                        <div>
                          <p className="font-mono text-sm text-slate-200">{run.targetHostname}</p>
                          <p className="font-mono text-[11px] text-slate-400">
                            {new Date(run.startedAt).toLocaleString()}
                          </p>
                        </div>
                        <span
                          className={`font-mono text-xs uppercase tracking-widest ${RUN_STATUS_STYLES[run.status] ?? "text-slate-400"}`}
                        >
                          {run.status.replace("_", " ")}
                        </span>
                      </Link>
                    ))}
                  </div>
                )}
              </section>
            </div>
          </>
        )}
      </div>
      {selectedFinding && <FindingDetailModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </Shell>
  );
}

function OwnTargetHeroCard({ targetId, hostname }: { targetId: string; hostname: string }) {
  const historyQuery = useQuery({
    queryKey: ["score-history", targetId],
    queryFn: () => fetchScoreHistory(targetId),
  });
  const latest = historyQuery.data?.at(-1);

  return (
    <Link
      to={`/targets/${targetId}`}
      className="block rounded-lg border border-neon-cyan/20 bg-panel/80 p-5 shadow-glow-cyan/0 transition hover:border-neon-cyan/50 hover:shadow-glow-cyan"
    >
      <div className="mb-3 flex items-start justify-between">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-neon-cyan">Own domain</p>
          <p className="font-display text-lg font-bold text-slate-100">{hostname}</p>
        </div>
        <GradeBadge grade={latest?.grade ?? null} score={latest ? Number(latest.overallScore) : null} />
      </div>
      <ScoreTrendChart history={historyQuery.data} compact />
    </Link>
  );
}
