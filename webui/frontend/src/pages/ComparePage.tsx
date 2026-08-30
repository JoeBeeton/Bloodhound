import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import type { CompareScoreMode } from "../components/CompareTrendChart";
import { CompareTrendChart } from "../components/CompareTrendChart";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { TargetTypeBadge } from "../components/TargetTypeBadge";
import { apiFetch } from "../lib/apiClient";
import type { CompareSeries, Target } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

async function fetchTargets(): Promise<Target[]> {
  const res = await apiFetch("/api/v1/targets");
  if (!res.ok) throw new Error("Failed to load targets.");
  return res.json();
}

async function fetchCompare(targetIds: string[]): Promise<CompareSeries[]> {
  const res = await apiFetch(`/api/v1/compare?targetIds=${targetIds.join(",")}`);
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
  const [selected, setSelected] = useState<Set<string> | null>(null);
  // Defaults to the fair-comparison score: Tier 2 (deep port scan, ZAP) only ever runs against
  // authorized targets - in practice, your own - so plotting the full score by default would
  // make your own domain look artificially worse than a competitor purely because it was
  // scanned more thoroughly, not because it's less secure.
  const [scoreMode, setScoreMode] = useState<CompareScoreMode>("tier1");

  // First render after targets load: default-select OWN targets. `selected`
  // stays null until then so we don't flash an empty chart before defaulting.
  const effectiveSelected = useMemo(() => {
    if (selected !== null) return selected;
    const ownIds = (targetsQuery.data ?? []).filter((t) => t.targetType === "OWN").map((t) => t.id);
    return new Set(ownIds);
  }, [selected, targetsQuery.data]);

  const targetIds = [...effectiveSelected];
  const compareQuery = useQuery({
    queryKey: ["compare", targetIds.sort().join(",")],
    queryFn: () => fetchCompare(targetIds),
    enabled: targetIds.length > 0,
  });

  function toggle(id: string) {
    const next = new Set(effectiveSelected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
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

            {compareQuery.isLoading && targetIds.length > 0 && (
              <p className="font-mono text-sm text-slate-400">Loading comparison…</p>
            )}
            {compareQuery.isError && (
              <ErrorState message="Failed to load comparison." onRetry={() => compareQuery.refetch()} />
            )}
            <CompareTrendChart series={targetIds.length > 0 ? compareQuery.data ?? [] : []} mode={scoreMode} />
          </>
        )}
      </div>
    </Shell>
  );
}
