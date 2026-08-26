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

async function fetchSubdomains(targetId: string): Promise<Subdomain[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/subdomains`);
  if (!res.ok) throw new Error("Failed to load subdomains.");
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
  const res = await apiFetch(`/api/v1/targets/${targetId}/findings?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load findings.");
  return res.json();
}

/** One subdomain's full fingerprint + the findings specifically attributed to it (affectedAsset = this hostname). */
export function SubdomainDetailPage() {
  const { id, hostname: encodedHostname } = useParams<{ id: string; hostname: string }>();
  const targetId = id!;
  const hostname = decodeURIComponent(encodedHostname!);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [filters, setFilters] = useState<FindingsFilterState>({ severities: [], categories: [] });

  const subdomainsQuery = useQuery({ queryKey: ["subdomains", targetId], queryFn: () => fetchSubdomains(targetId) });
  const fingerprintsQuery = useQuery({
    queryKey: ["fingerprints", targetId],
    queryFn: () => fetchFingerprints(targetId),
  });
  const findingsQuery = useQuery({
    queryKey: ["findings", targetId, hostname, filters],
    queryFn: () => fetchFindingsForHost(targetId, hostname, filters),
  });

  const subdomain = subdomainsQuery.data?.find((s) => s.hostname === hostname);
  const fingerprint = fingerprintsQuery.data?.find((f) => f.hostname === hostname);

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
            {filters.severities.length > 0 || filters.categories.length > 0
              ? "No findings match the selected filters."
              : "No open findings on this subdomain."}
          </p>
        )}
        <div className="flex flex-col gap-3">
          {findingsQuery.data?.map((finding) => (
            <FindingCard key={finding.id} finding={finding} onSelect={() => setSelectedFinding(finding)} />
          ))}
        </div>
      </div>
      {selectedFinding && <FindingDetailModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </Shell>
  );
}
