import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { FindingCard } from "../components/FindingCard";
import { FindingDetailModal } from "../components/FindingDetailModal";
import { FindingsFilterBar, type FindingsFilterState } from "../components/FindingsFilterBar";
import { FingerprintPanel } from "../components/TechHostingPanel";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import type { Finding, FingerprintEntry, Subdomain } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

/**
 * Single-hostname lookup, not "fetch the whole target's subdomain list and
 * find it client-side" (what this used to do) - a target can have tens of
 * thousands of subdomains (confirmed live, 57,107 for one real target), so
 * that would have meant a multi-second, multi-megabyte fetch just to load
 * one subdomain's detail page, and would have silently failed to find a
 * subdomain outside whatever page the (now-paginated) list endpoint
 * happened to return. 404 is a genuine "this subdomain doesn't exist for
 * this target" case, not an error - the query below just resolves to
 * null rather than throwing for it. Null, not undefined: TanStack Query v5 never settles a
 * query into "success" state for a queryFn that resolves to undefined (it's reserved to mean
 * "no data yet"), so isSuccess would never flip true and the 404 case would render as a
 * perpetual, indistinguishable loading state instead - confirmed live before this was null.
 */
async function fetchSubdomain(targetId: string, hostname: string): Promise<Subdomain | null> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/subdomains/${encodeURIComponent(hostname)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("Failed to load subdomain.");
  return res.json();
}

async function fetchFingerprints(targetId: string): Promise<FingerprintEntry[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/fingerprints`);
  if (!res.ok) throw new Error("Failed to load fingerprint data.");
  return res.json();
}

async function fetchFindingsForHost(
  targetId: string,
  hostname: string,
  filters: FindingsFilterState,
): Promise<Finding[]> {
  const params = new URLSearchParams({ affectedAsset: hostname });
  if (filters.severities.length > 0) params.set("severity", filters.severities.join(","));
  if (filters.categories.length > 0) params.set("category", filters.categories.join(","));
  if (filters.status === "RESOLVED") params.set("status", "RESOLVED");
  if (filters.search) params.set("search", filters.search);
  const res = await apiFetch(`/api/v1/targets/${targetId}/findings?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load findings.");
  return res.json();
}

/** One subdomain's full fingerprint + the findings specifically attributed to it (affectedAsset = this hostname). */
export function SubdomainDetailPage() {
  const { id, hostname: encodedHostname } = useParams<{ id: string; hostname: string }>();
  const targetId = id!;
  const hostname = decodeURIComponent(encodedHostname!);
  usePageTitle(hostname);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [filters, setFilters] = useState<FindingsFilterState>({ severities: [], categories: [] });

  const subdomainQuery = useQuery({
    queryKey: ["subdomain", targetId, hostname],
    queryFn: () => fetchSubdomain(targetId, hostname),
  });
  const fingerprintsQuery = useQuery({
    queryKey: ["fingerprints", targetId],
    queryFn: () => fetchFingerprints(targetId),
  });
  const findingsQuery = useQuery({
    queryKey: ["findings", targetId, hostname, filters],
    queryFn: () => fetchFindingsForHost(targetId, hostname, filters),
  });

  const subdomain = subdomainQuery.data;
  const fingerprint = fingerprintsQuery.data?.find((f) => f.hostname === hostname);
  // fetchSubdomain resolves 404 to null rather than throwing (see its own comment) - that
  // needs its own branch here, or a pruned/mistyped hostname would silently render as an empty
  // "no findings, no tech data" page instead of the "this isn't tracked" it actually is.
  const notFound = subdomainQuery.isSuccess && subdomain === null;

  return (
    <Shell>
      <div className="w-full max-w-3xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Subdomain</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">{hostname}</h1>
            {subdomain && (
              <p className="mt-1 font-mono text-xs uppercase tracking-widest text-slate-400">
                First seen {new Date(subdomain.firstSeenAt).toLocaleDateString()} · last seen{" "}
                {new Date(subdomain.lastSeenAt).toLocaleDateString()}
                {subdomain.currentIpAddresses.length > 0 ? ` · ${subdomain.currentIpAddresses.join(", ")}` : ""}
              </p>
            )}
          </div>
          <Link
            to={`/targets/${targetId}/subdomains`}
            className="shrink-0 font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan"
          >
            ← Subdomains
          </Link>
        </div>

        {notFound ? (
          <div className="rounded-lg border border-severity-critical/30 bg-panel/60 px-6 py-10 text-center">
            <p className="font-mono text-sm text-slate-300">This subdomain isn't tracked for this target.</p>
            <p className="mt-1 font-mono text-xs text-slate-500">
              It may have been pruned since the link was created, or the hostname may be mistyped.
            </p>
            <Link
              to={`/targets/${targetId}/subdomains`}
              className="mt-4 inline-block rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10"
            >
              ← View tracked subdomains
            </Link>
          </div>
        ) : (
          <>
            <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-400">Technology &amp; hosting</h2>
            <div className="mb-10">
              {fingerprintsQuery.isLoading ? (
                <p className="font-mono text-sm text-slate-400">Loading technology &amp; hosting data…</p>
              ) : fingerprintsQuery.isError ? (
                <ErrorState message="Failed to load technology & hosting data." onRetry={() => fingerprintsQuery.refetch()} />
              ) : (
                <FingerprintPanel fingerprint={fingerprint} />
              )}
            </div>

            <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-400">
              Open findings {findingsQuery.data ? `(${findingsQuery.data.length})` : ""}
            </h2>
            <FindingsFilterBar value={filters} onChange={setFilters} resultCount={findingsQuery.data?.length} />
            {findingsQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading findings…</p>}
            {findingsQuery.isError && (
              <ErrorState message="Failed to load findings." onRetry={() => findingsQuery.refetch()} />
            )}
            {findingsQuery.data?.length === 0 && (
              <p className="font-mono text-sm text-slate-400">
                {filters.severities.length > 0 || filters.categories.length > 0 || filters.search
                  ? "No findings match the selected filters."
                  : filters.status === "RESOLVED"
                    ? "Nothing resolved yet."
                    : "No open findings on this subdomain."}
              </p>
            )}
            <div className="flex flex-col gap-3">
              {findingsQuery.data?.map((finding) => (
                <FindingCard key={finding.id} finding={finding} onSelect={() => setSelectedFinding(finding)} />
              ))}
            </div>
          </>
        )}
      </div>
      {selectedFinding && <FindingDetailModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </Shell>
  );
}
