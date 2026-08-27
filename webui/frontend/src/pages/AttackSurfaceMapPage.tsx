import { useMemo } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { AttackSurfaceGraph } from "../components/AttackSurfaceGraph";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch, totalCountFromResponse } from "../lib/apiClient";
import { buildGraph, SUBDOMAINS_PER_TARGET_CAP } from "../lib/attackSurfaceGraph";
import type { Subdomain, Target } from "../lib/types";

async function fetchTargets(): Promise<Target[]> {
  const res = await apiFetch("/api/v1/targets");
  if (!res.ok) throw new Error("Failed to load targets.");
  return res.json();
}

async function fetchSubdomainSample(targetId: string): Promise<{ sample: Subdomain[]; total: number }> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/subdomains?limit=${SUBDOMAINS_PER_TARGET_CAP}`);
  if (!res.ok) throw new Error("Failed to load subdomains.");
  const sample: Subdomain[] = await res.json();
  return { sample, total: totalCountFromResponse(res, sample.length) };
}

/**
 * The whole org's tracked attack surface as one force-directed map: your org at the center,
 * every tracked target orbiting it (own/competitor/watchlist loosely clustered by color - see
 * AttackSurfaceGraph), and each target's own discovered subdomains orbiting it in turn. A visual
 * complement to the tabular /targets and /targets/:id/subdomains views, not a replacement for
 * either - this is for seeing the shape of what's being watched at a glance, the table views are
 * still where you go to actually search/filter/act on a specific host.
 */
export function AttackSurfaceMapPage() {
  const targetsQuery = useQuery({ queryKey: ["targets"], queryFn: fetchTargets });
  const targets = targetsQuery.data ?? [];

  const subdomainQueries = useQueries({
    queries: targets.map((t) => ({
      queryKey: ["subdomain-sample", t.id],
      queryFn: () => fetchSubdomainSample(t.id),
      enabled: targetsQuery.isSuccess,
    })),
  });

  const subdomainsLoaded = targets.length > 0 && subdomainQueries.every((q) => q.isSuccess);

  const graph = useMemo(() => {
    if (!subdomainsLoaded) return null;
    const byTarget = new Map(targets.map((t, i) => [t.id, subdomainQueries[i].data!]));
    return buildGraph(targets, byTarget);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subdomainsLoaded, targets]);

  const totalSubdomains = subdomainQueries.reduce((sum, q) => sum + (q.data?.total ?? 0), 0);
  const isLoading = targetsQuery.isLoading || (targets.length > 0 && !subdomainsLoaded && !subdomainQueries.some((q) => q.isError));
  const hasError = targetsQuery.isError || subdomainQueries.some((q) => q.isError);

  return (
    <Shell>
      <div className="flex w-full max-w-6xl flex-col gap-6 text-left">
        <div>
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Visualize</p>
          <h1 className="font-display text-3xl font-bold text-neon-cyan">Attack Surface Map</h1>
          <p className="mt-2 max-w-2xl font-mono text-xs text-slate-400">
            {targets.length > 0
              ? `${targets.length} target${targets.length === 1 ? "" : "s"} tracked, ${totalSubdomains.toLocaleString()} known host${totalSubdomains === 1 ? "" : "s"} across them.`
              : "Every target you track and what's been discovered under it, laid out as one map."}
          </p>
        </div>

        {isLoading && <p className="font-mono text-sm text-slate-400">Mapping your attack surface…</p>}
        {hasError && <ErrorState message="Failed to load the attack surface map." onRetry={() => targetsQuery.refetch()} />}
        {!isLoading && !hasError && targets.length === 0 && (
          <p className="font-mono text-sm text-slate-400">No targets tracked yet — add one to see it here.</p>
        )}
        {graph && <AttackSurfaceGraph data={graph} />}
      </div>
    </Shell>
  );
}
