import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import type { CompareScoreMode } from "../components/CompareTrendChart";
import { CompareTrendChart } from "../components/CompareTrendChart";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { TargetTypeBadge } from "../components/TargetTypeBadge";
import { apiFetch } from "../lib/apiClient";
import type { CompareSeries, Portfolio, Target } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

async function fetchTargets(): Promise<Target[]> {
  const res = await apiFetch("/api/v1/targets");
  if (!res.ok) throw new Error("Failed to load targets.");
  return res.json();
}

async function fetchPortfolios(): Promise<Portfolio[]> {
  const res = await apiFetch("/api/v1/portfolios");
  if (!res.ok) throw new Error("Failed to load portfolios.");
  return res.json();
}

/** targetIds and portfolioIds are independent selections - either (or both) can be empty; the backend accepts either param missing entirely. */
async function fetchCompare(targetIds: string[], portfolioIds: string[]): Promise<CompareSeries[]> {
  const params = new URLSearchParams();
  if (targetIds.length > 0) params.set("targetIds", targetIds.join(","));
  if (portfolioIds.length > 0) params.set("portfolioIds", portfolioIds.join(","));
  const res = await apiFetch(`/api/v1/compare?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load comparison.");
  return res.json();
}

/**
 * The headline differential-analysis screen: your own domain(s) plotted
 * alongside any number of competitor/watchlist domains' score histories.
 * Defaults to selecting the org's OWN targets so the page isn't empty on
 * first load, without assuming which competitors matter to the viewer.
 */
export function ComparePage() {
  usePageTitle("Compare");
  const targetsQuery = useQuery({ queryKey: ["targets"], queryFn: fetchTargets });
  const portfoliosQuery = useQuery({ queryKey: ["portfolios"], queryFn: fetchPortfolios });
  // A product review found a comparison you'd actually built - a specific set of competitor
  // domains, in "full picture" mode - vanished the moment the tab was reloaded or the URL was
  // shared with a colleague, silently reverting to the OWN-targets default. Persisted in the URL
  // (same convention FindingsPage/TargetDetailPage already use for their own filter state)
  // instead of component state, so both reload and sharing a link now reproduce the exact view.
  const [searchParams, setSearchParams] = useSearchParams();
  const urlTargetIds = searchParams.get("targetIds");
  // Defaults to the fair-comparison score: Tier 2 (deep port scan, ZAP) only ever runs against
  // authorized targets - in practice, your own - so plotting the full score by default would
  // make your own domain look artificially worse than a competitor purely because it was
  // scanned more thoroughly, not because it's less secure.
  const scoreMode: CompareScoreMode = searchParams.get("mode") === "full" ? "full" : "tier1";

  // Absent from the URL entirely: default-select OWN targets. An explicit (even empty)
  // targetIds param always wins, so a deliberately-cleared selection stays cleared on reload
  // rather than snapping back to the default.
  const effectiveSelected = useMemo(() => {
    if (urlTargetIds !== null) return new Set(urlTargetIds.split(",").filter(Boolean));
    const ownIds = (targetsQuery.data ?? []).filter((t) => t.targetType === "OWN").map((t) => t.id);
    return new Set(ownIds);
  }, [urlTargetIds, targetsQuery.data]);

  // No default selection, unlike targets' "default to OWN" above - a portfolio is something the
  // user deliberately created and picks explicitly, there's no equivalent "obvious default" for it.
  const urlPortfolioIds = searchParams.get("portfolioIds");
  const effectiveSelectedPortfolios = useMemo(
    () => new Set(urlPortfolioIds ? urlPortfolioIds.split(",").filter(Boolean) : []),
    [urlPortfolioIds],
  );

  const targetIds = [...effectiveSelected];
  const portfolioIds = [...effectiveSelectedPortfolios];
  const compareQuery = useQuery({
    queryKey: ["compare", targetIds.sort().join(","), portfolioIds.sort().join(",")],
    queryFn: () => fetchCompare(targetIds, portfolioIds),
    enabled: targetIds.length > 0 || portfolioIds.length > 0,
  });

  function toggle(id: string) {
    const next = new Set(effectiveSelected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        params.set("targetIds", [...next].join(","));
        return params;
      },
      { replace: true },
    );
  }

  function togglePortfolio(id: string) {
    const next = new Set(effectiveSelectedPortfolios);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        params.set("portfolioIds", [...next].join(","));
        return params;
      },
      { replace: true },
    );
  }

  function setScoreMode(mode: CompareScoreMode) {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        mode === "tier1" ? params.delete("mode") : params.set("mode", "full");
        return params;
      },
      { replace: true },
    );
  }

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Differential Analysis</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">Compare</h1>
          </div>
          <Link to="/targets" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
            ← Targets
          </Link>
        </div>

        {targetsQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading targets…</p>}
        {targetsQuery.isError && (
          <ErrorState message="Failed to load targets." onRetry={() => targetsQuery.refetch()} />
        )}
        {targetsQuery.data?.length === 0 && (
          <p className="font-mono text-sm text-slate-400">No targets yet — add one on the Targets page first.</p>
        )}

        {targetsQuery.data && targetsQuery.data.length > 0 && (
          <>
            <div className="mb-6 flex flex-wrap gap-2 rounded-lg border border-neon-cyan/20 bg-panel/60 p-4">
              {targetsQuery.data.map((target) => {
                const isSelected = effectiveSelected.has(target.id);
                return (
                  <button
                    key={target.id}
                    aria-pressed={isSelected}
                    onClick={() => toggle(target.id)}
                    className={`flex items-center gap-2 rounded border px-2.5 py-1.5 font-mono text-xs transition ${
                      isSelected
                        ? "border-neon-cyan bg-neon-cyan/10 text-neon-cyan"
                        : "border-slate-700 text-slate-400 hover:border-slate-500"
                    }`}
                  >
                    <span>{target.hostname}</span>
                    <TargetTypeBadge targetType={target.targetType} />
                  </button>
                );
              })}
            </div>

            {portfoliosQuery.data && portfoliosQuery.data.length > 0 && (
              <div className="mb-6">
                <p className="mb-2 font-mono text-xs uppercase tracking-widest text-slate-400">Portfolios</p>
                <div className="flex flex-wrap gap-2 rounded-lg border border-neon-magenta/20 bg-panel/60 p-4">
                  {portfoliosQuery.data.map((portfolio) => {
                    const isSelected = effectiveSelectedPortfolios.has(portfolio.id);
                    return (
                      <button
                        key={portfolio.id}
                        aria-pressed={isSelected}
                        onClick={() => togglePortfolio(portfolio.id)}
                        className={`flex items-center gap-2 rounded border px-2.5 py-1.5 font-mono text-xs transition ${
                          isSelected
                            ? "border-neon-magenta bg-neon-magenta/10 text-neon-magenta"
                            : "border-slate-700 text-slate-400 hover:border-slate-500"
                        }`}
                      >
                        {portfolio.name}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div
                role="group"
                aria-label="Score mode"
                className="inline-flex rounded border border-neon-cyan/20 bg-panel/60 p-0.5 font-mono text-xs uppercase tracking-widest"
              >
                <button
                  aria-pressed={scoreMode === "tier1"}
                  onClick={() => setScoreMode("tier1")}
                  className={`rounded px-3 py-1.5 transition ${
                    scoreMode === "tier1" ? "bg-neon-cyan/15 text-neon-cyan" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Fair comparison
                </button>
                <button
                  aria-pressed={scoreMode === "full"}
                  onClick={() => setScoreMode("full")}
                  className={`rounded px-3 py-1.5 transition ${
                    scoreMode === "full" ? "bg-neon-magenta/15 text-neon-magenta" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Full picture
                </button>
              </div>
              <p className="max-w-md text-right font-mono text-[11px] leading-tight text-slate-500">
                {scoreMode === "tier1"
                  ? "Tier 1 findings only — the same scope every tracked domain gets, so scores are directly comparable."
                  : "Includes findings from authorized deep scans, which only ever run against your own domains."}
              </p>
            </div>

            {compareQuery.isLoading && (targetIds.length > 0 || portfolioIds.length > 0) && (
              <p className="font-mono text-sm text-slate-400">Loading comparison…</p>
            )}
            {compareQuery.isError && (
              <ErrorState message="Failed to load comparison." onRetry={() => compareQuery.refetch()} />
            )}
            <CompareTrendChart
              series={targetIds.length > 0 || portfolioIds.length > 0 ? (compareQuery.data ?? []) : []}
              mode={scoreMode}
            />
          </>
        )}
      </div>
    </Shell>
  );
}
