import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import type { CompareScoreMode } from "../components/CompareTrendChart";
import { CompareTrendChart } from "../components/CompareTrendChart";
import { CompareCategoryChart } from "../components/CompareCategoryChart";
import { CompareFindingsChart } from "../components/CompareFindingsChart";
import { CompareLeaderboard } from "../components/CompareLeaderboard";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { TargetTypeBadge } from "../components/TargetTypeBadge";
import { apiFetch } from "../lib/apiClient";
import type { CompareSeries, Portfolio, Target } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

const VIEW_MODES = ["trend", "categories", "findings", "leaderboard"] as const;
type ViewMode = (typeof VIEW_MODES)[number];
const VIEW_MODE_LABELS: Record<ViewMode, string> = {
  trend: "Trend",
  categories: "Categories",
  findings: "Findings",
  leaderboard: "Leaderboard",
};

// A competitor-UX review (UpGuard, which lets a comparison span the past month/quarter/year)
// found this page had no equivalent at all - every view always plotted a target's ENTIRE
// available history, with no way to zoom to a recent window. "all" (the default) preserves the
// page's prior behavior exactly, so existing shared/bookmarked URLs keep showing what they always
// showed; the filter is purely additive.
const RANGES = ["30d", "90d", "1y", "all"] as const;
type RangeFilter = (typeof RANGES)[number];
const RANGE_LABELS: Record<RangeFilter, string> = {
  "30d": "30d",
  "90d": "90d",
  "1y": "1y",
  all: "All time",
};
const RANGE_DAYS: Record<Exclude<RangeFilter, "all">, number> = {
  "30d": 30,
  "90d": 90,
  "1y": 365,
};

/** Only Trend (which plots every point) and Leaderboard's "change since" delta (which anchors on
 * the window's own first point) are actually affected by the range - Categories/Findings always
 * read just the latest snapshot regardless, so filtering history before it reaches any view keeps
 * that correct for free rather than needing each view to know about ranges itself. */
function applyRange(
  series: CompareSeries[],
  range: RangeFilter,
): CompareSeries[] {
  if (range === "all") return series;
  const cutoffMs = Date.now() - RANGE_DAYS[range] * 24 * 60 * 60 * 1000;
  return series.map((s) => ({
    ...s,
    history: s.history.filter(
      (h) => new Date(h.computedAt).getTime() >= cutoffMs,
    ),
  }));
}

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
async function fetchCompare(
  targetIds: string[],
  portfolioIds: string[],
): Promise<CompareSeries[]> {
  const params = new URLSearchParams();
  if (targetIds.length > 0) params.set("targetIds", targetIds.join(","));
  if (portfolioIds.length > 0)
    params.set("portfolioIds", portfolioIds.join(","));
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
  const targetsQuery = useQuery({
    queryKey: ["targets"],
    queryFn: fetchTargets,
  });
  const portfoliosQuery = useQuery({
    queryKey: ["portfolios"],
    queryFn: fetchPortfolios,
  });
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
  const scoreMode: CompareScoreMode =
    searchParams.get("mode") === "full" ? "full" : "tier1";
  const urlView = searchParams.get("view");
  const viewMode: ViewMode = VIEW_MODES.includes(urlView as ViewMode)
    ? (urlView as ViewMode)
    : "trend";
  const urlRange = searchParams.get("range");
  const range: RangeFilter = RANGES.includes(urlRange as RangeFilter)
    ? (urlRange as RangeFilter)
    : "all";

  // Absent from the URL entirely: default-select every portfolio (see effectiveSelectedPortfolios
  // just below) and every OWN target that ISN'T already one of their members - a portfolio's own
  // blended line already represents its members, so defaulting both on at once would double them
  // up in the same chart/table for no reason. An explicit (even empty) targetIds param always
  // wins, so a deliberately-cleared selection stays cleared on reload rather than snapping back to
  // the default.
  const portfolioMemberIds = useMemo(
    () =>
      new Set((portfoliosQuery.data ?? []).flatMap((p) => p.memberTargetIds)),
    [portfoliosQuery.data],
  );
  const effectiveSelected = useMemo(() => {
    if (urlTargetIds !== null)
      return new Set(urlTargetIds.split(",").filter(Boolean));
    const ownIds = (targetsQuery.data ?? [])
      .filter((t) => t.targetType === "OWN" && !portfolioMemberIds.has(t.id))
      .map((t) => t.id);
    return new Set(ownIds);
  }, [urlTargetIds, targetsQuery.data, portfolioMemberIds]);

  // Defaults to every portfolio that exists, unlike the pre-portfolio-support version of this
  // page (which had no obvious default for it) - a portfolio is something the user deliberately
  // created specifically to be watched, so it should show up without having to be clicked on every
  // single visit, the same way a newly-added OWN target already does for the targets list above.
  const urlPortfolioIds = searchParams.get("portfolioIds");
  const effectiveSelectedPortfolios = useMemo(() => {
    if (urlPortfolioIds !== null)
      return new Set(urlPortfolioIds.split(",").filter(Boolean));
    return new Set((portfoliosQuery.data ?? []).map((p) => p.id));
  }, [urlPortfolioIds, portfoliosQuery.data]);

  const targetIds = [...effectiveSelected];
  const portfolioIds = [...effectiveSelectedPortfolios];
  const compareQuery = useQuery({
    queryKey: [
      "compare",
      targetIds.sort().join(","),
      portfolioIds.sort().join(","),
    ],
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

  function setViewMode(view: ViewMode) {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        view === "trend" ? params.delete("view") : params.set("view", view);
        return params;
      },
      { replace: true },
    );
  }

  function setRange(next: RangeFilter) {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        next === "all" ? params.delete("range") : params.set("range", next);
        return params;
      },
      { replace: true },
    );
  }

  return (
    <Shell>
      <div className="w-full max-w-6xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">
              Differential Analysis
            </p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">
              Compare
            </h1>
          </div>
          <Link
            to="/targets"
            className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan"
          >
            ← Targets
          </Link>
        </div>

        {targetsQuery.isLoading && (
          <p className="font-mono text-sm text-slate-400">Loading targets…</p>
        )}
        {targetsQuery.isError && (
          <ErrorState
            message="Failed to load targets."
            onRetry={() => targetsQuery.refetch()}
          />
        )}
        {targetsQuery.data?.length === 0 && (
          <p className="font-mono text-sm text-slate-400">
            No targets yet — add one on the Targets page first.
          </p>
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
                <p className="mb-2 font-mono text-xs uppercase tracking-widest text-slate-400">
                  Portfolios
                </p>
                <div className="flex flex-wrap gap-2 rounded-lg border border-neon-magenta/20 bg-panel/60 p-4">
                  {portfoliosQuery.data.map((portfolio) => {
                    const isSelected = effectiveSelectedPortfolios.has(
                      portfolio.id,
                    );
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
                aria-label="View"
                className="inline-flex rounded border border-neon-cyan/20 bg-panel/60 p-0.5 font-mono text-xs uppercase tracking-widest"
              >
                {VIEW_MODES.map((view) => (
                  <button
                    key={view}
                    aria-pressed={viewMode === view}
                    onClick={() => setViewMode(view)}
                    className={`rounded px-3 py-1.5 transition ${
                      viewMode === view
                        ? "bg-neon-cyan/15 text-neon-cyan"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {VIEW_MODE_LABELS[view]}
                  </button>
                ))}
              </div>

              {/* Only Trend (which plots every point) and Leaderboard (whose "change" column
                  anchors on the window's own first point) are actually affected by range -
                  Categories/Findings always read just the latest snapshot, so the control is
                  hidden there rather than shown doing nothing, same reasoning as the score-mode
                  toggle's own conditional below. */}
              {(viewMode === "trend" || viewMode === "leaderboard") && (
                <div
                  role="group"
                  aria-label="Time range"
                  className="inline-flex rounded border border-neon-cyan/20 bg-panel/60 p-0.5 font-mono text-xs uppercase tracking-widest"
                >
                  {RANGES.map((r) => (
                    <button
                      key={r}
                      aria-pressed={range === r}
                      onClick={() => setRange(r)}
                      className={`rounded px-3 py-1.5 transition ${
                        range === r
                          ? "bg-neon-cyan/15 text-neon-cyan"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {RANGE_LABELS[r]}
                    </button>
                  ))}
                </div>
              )}

              {/* findingCounts carries no tier1/full split (see CompareFindingsChart's own doc
                  comment) - this toggle has no effect on that view, so it's hidden there rather
                  than shown doing nothing. */}
              {viewMode !== "findings" && (
                <div
                  role="group"
                  aria-label="Score mode"
                  className="inline-flex rounded border border-neon-cyan/20 bg-panel/60 p-0.5 font-mono text-xs uppercase tracking-widest"
                >
                  <button
                    aria-pressed={scoreMode === "tier1"}
                    onClick={() => setScoreMode("tier1")}
                    className={`rounded px-3 py-1.5 transition ${
                      scoreMode === "tier1"
                        ? "bg-neon-cyan/15 text-neon-cyan"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Fair comparison
                  </button>
                  <button
                    aria-pressed={scoreMode === "full"}
                    onClick={() => setScoreMode("full")}
                    className={`rounded px-3 py-1.5 transition ${
                      scoreMode === "full"
                        ? "bg-neon-magenta/15 text-neon-magenta"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Full picture
                  </button>
                </div>
              )}
            </div>
            {viewMode !== "findings" && (
              <p className="mb-3 text-right font-mono text-[11px] leading-tight text-slate-500">
                {scoreMode === "tier1"
                  ? "Tier 1 findings only — the same scope every tracked domain gets, so scores are directly comparable."
                  : "Includes findings from authorized deep scans, which only ever run against your own domains."}
              </p>
            )}

            {compareQuery.isLoading &&
              (targetIds.length > 0 || portfolioIds.length > 0) && (
                <p className="font-mono text-sm text-slate-400">
                  Loading comparison…
                </p>
              )}
            {compareQuery.isError && (
              <ErrorState
                message="Failed to load comparison."
                onRetry={() => compareQuery.refetch()}
              />
            )}
            {(() => {
              const activeSeries =
                targetIds.length > 0 || portfolioIds.length > 0
                  ? (compareQuery.data ?? [])
                  : [];
              // Categories/Findings always read just the latest snapshot regardless of range (see
              // the range control's own conditional above) - ranging their input could otherwise
              // wrongly show "no history" when the most recent real scan simply predates the
              // selected window, rather than not existing at all.
              const rangedSeries = applyRange(activeSeries, range);
              switch (viewMode) {
                case "categories":
                  return (
                    <CompareCategoryChart
                      series={activeSeries}
                      mode={scoreMode}
                    />
                  );
                case "findings":
                  return <CompareFindingsChart series={activeSeries} />;
                case "leaderboard":
                  return (
                    <CompareLeaderboard
                      series={rangedSeries}
                      mode={scoreMode}
                    />
                  );
                default:
                  return (
                    <CompareTrendChart series={rangedSeries} mode={scoreMode} />
                  );
              }
            })()}
          </>
        )}
      </div>
    </Shell>
  );
}
