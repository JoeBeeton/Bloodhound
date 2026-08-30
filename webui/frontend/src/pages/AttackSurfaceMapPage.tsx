import { useMemo } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { AttackSurfaceGraph } from "../components/AttackSurfaceGraph";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch, totalCountFromResponse } from "../lib/apiClient";
import { buildGraph, SUBDOMAINS_PER_TARGET_CAP } from "../lib/attackSurfaceGraph";
import type { Subdomain, Target, WorkerStatus } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

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

async function fetchWorkers(): Promise<WorkerStatus[]> {
  const res = await apiFetch("/api/v1/workers");
  if (!res.ok) throw new Error("Failed to load workers.");
  return res.json();
}

/** Same cadence as WorkerPanel/ScansPage - "what's happening right now" views all poll at the same rate, no reason for a second timer. */
const WORKER_POLL_INTERVAL_MS = 5000;

/**
 * The whole picture as one force-directed map: central-server at the hub with the platform's
 * own topology (postgres, webui, live workers - see AttackSurfaceGraph) clustered to one side,
 * and every tracked target - own/competitor/watchlist loosely clustered by color, each with its
 * own discovered subdomains orbiting it - clustered elsewhere. A worker actively scanning a
 * target gets a live animated link straight to it, so the platform doing the work and the
 * surface it's watching show up on the same map. A visual complement to the tabular /targets,
 * /targets/:id/subdomains, and worker-status views, not a replacement for any of them - this is
 * for seeing the shape of the whole system at a glance, the table/list views are still where you
 * go to actually search/filter/act on a specific host or job.
 */
export function AttackSurfaceMapPage() {
  usePageTitle("Attack Surface Map");
  const targetsQuery = useQuery({ queryKey: ["targets"], queryFn: fetchTargets });
  const targets = targetsQuery.data ?? [];

  const workersQuery = useQuery({
    queryKey: ["workers"],
    queryFn: fetchWorkers,
    refetchInterval: WORKER_POLL_INTERVAL_MS,
  });

  const subdomainQueries = useQueries({
    queries: targets.map((t) => ({
      queryKey: ["subdomain-sample", t.id],
      queryFn: () => fetchSubdomainSample(t.id),
      enabled: targetsQuery.isSuccess,
    })),
  });

  const subdomainsLoaded = targets.length === 0 || subdomainQueries.every((q) => q.isSuccess);

  const graph = useMemo(() => {
    if (!targetsQuery.isSuccess || !subdomainsLoaded) return null;
    const byTarget = new Map(targets.map((t, i) => [t.id, subdomainQueries[i]?.data]).filter((e): e is [string, { sample: Subdomain[]; total: number }] => e[1] != null));
    // Workers are a live overlay, not something the whole map should block on - an empty list
    // (still loading, or the query failed) just means no worker nodes/scanning links yet, same
    // as WorkerPanel's own independent error handling for this exact endpoint.
    return buildGraph(targets, byTarget, workersQuery.data ?? []);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetsQuery.isSuccess, subdomainsLoaded, targets, workersQuery.data]);

  const totalSubdomains = subdomainQueries.reduce((sum, q) => sum + (q.data?.total ?? 0), 0);
  const isLoading = targetsQuery.isLoading || (targets.length > 0 && !subdomainsLoaded && !subdomainQueries.some((q) => q.isError));
  const hasError = targetsQuery.isError || subdomainQueries.some((q) => q.isError);
  const activeWorkerCount = workersQuery.data?.filter((w) => w.status !== "OFFLINE").length ?? 0;

  return (
    <Shell>
      <div className="flex w-full max-w-6xl flex-col gap-6 text-left">
        <div>
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Visualize</p>
          <h1 className="font-display text-3xl font-bold text-neon-cyan">Attack Surface Map</h1>
          <p className="mt-2 max-w-2xl font-mono text-xs text-slate-400">
            {targets.length > 0
              ? `${targets.length} target${targets.length === 1 ? "" : "s"} tracked, ${totalSubdomains.toLocaleString()} known host${totalSubdomains === 1 ? "" : "s"} across them` +
                (activeWorkerCount > 0 ? ` · ${activeWorkerCount} worker${activeWorkerCount === 1 ? "" : "s"} online.` : ".")
              : "Every target you track, what's been discovered under it, and the platform doing the scanning - laid out as one map."}
          </p>
        </div>

        {isLoading && <p className="font-mono text-sm text-slate-400">Mapping your attack surface…</p>}
        {hasError && <ErrorState message="Failed to load the attack surface map." onRetry={() => targetsQuery.refetch()} />}
        {!isLoading && !hasError && graph && <AttackSurfaceGraph data={graph} />}
      </div>
    </Shell>
  );
}
