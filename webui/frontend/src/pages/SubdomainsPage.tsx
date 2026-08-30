import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { HostingBadge } from "../components/TechHostingPanel";
import { Shell } from "../components/Shell";
import { apiFetch, totalCountFromResponse } from "../lib/apiClient";
import type { Finding, FingerprintEntry, Severity, Subdomain, Target } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

/** Server-capped page plus the true match count - see totalCountFromResponse; a target can have far more rows than the server will ever return in one request (confirmed live: 57,107 subdomains / 36,466 findings for one real target). */
interface Page<T> {
  items: T[];
  totalCount: number;
}

/** Comfortably above what any normal target has, while staying well under the server's hard cap - large enough that this page's "full inventory" framing stays true for the vast majority of targets. */
const PAGE_LIMIT = 500;

async function fetchTarget(id: string): Promise<Target> {
  const res = await apiFetch(`/api/v1/targets/${id}`);
  if (!res.ok) throw new Error("Failed to load target.");
  return res.json();
}

async function fetchSubdomains(targetId: string, hostnameSearch: string): Promise<Page<Subdomain>> {
  const params = new URLSearchParams({ limit: String(PAGE_LIMIT) });
  if (hostnameSearch) params.set("hostname", hostnameSearch);
  const res = await apiFetch(`/api/v1/targets/${targetId}/subdomains?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load subdomains.");
  const items: Subdomain[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
}

async function fetchFingerprints(targetId: string): Promise<FingerprintEntry[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/fingerprints`);
  if (!res.ok) throw new Error("Failed to load fingerprint data.");
  return res.json();
}

async function fetchFindings(targetId: string): Promise<Page<Finding>> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/findings?limit=${PAGE_LIMIT}`);
  if (!res.ok) throw new Error("Failed to load findings.");
  const items: Finding[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_TEXT: Record<Severity, string> = {
  CRITICAL: "text-severity-critical",
  HIGH: "text-severity-high",
  MEDIUM: "text-severity-medium",
  LOW: "text-severity-low",
  INFO: "text-severity-info",
};
const SEVERITY_WEIGHT: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

function highestSeverity(severities: Severity[]): Severity | null {
  for (const s of SEVERITY_ORDER) {
    if (severities.includes(s)) return s;
  }
  return null;
}

/** Worst-first: the whole point of this sort mode is triage - "which subdomain needs
 * attention first" - so it ranks by severity before count, same convention ScansPage's
 * STATUS_PRIORITY and TargetDetailPage's score-impact sort both already use. */
export function byMostSevereFindingsFirst(rows: Subdomain[], findingsByHostname: Map<string, Finding[]>): Subdomain[] {
  return rows.slice().sort((a, b) => {
    const findingsA = findingsByHostname.get(a.hostname) ?? [];
    const findingsB = findingsByHostname.get(b.hostname) ?? [];
    const worstA = highestSeverity(findingsA.map((f) => f.severity));
    const worstB = highestSeverity(findingsB.map((f) => f.severity));
    const weightA = worstA ? SEVERITY_WEIGHT[worstA] : -1;
    const weightB = worstB ? SEVERITY_WEIGHT[worstB] : -1;
    return weightB - weightA || findingsB.length - findingsA.length;
  });
}

/** Full subdomain inventory for a target: fingerprint + open-findings summary per subdomain, clicking through to detail. */
export function SubdomainsPage() {
  const { id } = useParams<{ id: string }>();
  const targetId = id!;
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [sortByFindings, setSortByFindings] = useState(false);
  // Debounced so typing doesn't fire a request per keystroke - the search now genuinely
  // queries the server (see fetchSubdomains), not just the already-fetched page, so it's
  // a real network round trip each time it changes.
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(timer);
  }, [search]);

  const targetQuery = useQuery({ queryKey: ["target", targetId], queryFn: () => fetchTarget(targetId) });
  usePageTitle(targetQuery.data ? `Subdomains: ${targetQuery.data.hostname}` : null);
  const subdomainsQuery = useQuery({
    queryKey: ["subdomains", targetId, debouncedSearch],
    queryFn: () => fetchSubdomains(targetId, debouncedSearch),
  });
  const fingerprintsQuery = useQuery({
    queryKey: ["fingerprints", targetId],
    queryFn: () => fetchFingerprints(targetId),
  });
  const findingsQuery = useQuery({ queryKey: ["findings", targetId], queryFn: () => fetchFindings(targetId) });

  const fingerprintsByHostname = useMemo(
    () => new Map((fingerprintsQuery.data ?? []).map((f) => [f.hostname, f])),
    [fingerprintsQuery.data],
  );

  const findingsByHostname = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findingsQuery.data?.items ?? []) {
      const list = map.get(f.affectedAsset) ?? [];
      list.push(f);
      map.set(f.affectedAsset, list);
    }
    return map;
  }, [findingsQuery.data]);

  // Filtering now happens server-side (see fetchSubdomains's hostname param) so this page
  // stays correct against a target's FULL subdomain set, not just whatever page was
  // fetched - filtered === subdomains, kept as its own name only so the JSX below reads
  // the same as before.
  const filtered = sortByFindings
    ? byMostSevereFindingsFirst(subdomainsQuery.data?.items ?? [], findingsByHostname)
    : (subdomainsQuery.data?.items ?? []);
  const subdomainsTruncated = !!subdomainsQuery.data && subdomainsQuery.data.totalCount > subdomainsQuery.data.items.length;
  const findingsTruncated = !!findingsQuery.data && findingsQuery.data.totalCount > findingsQuery.data.items.length;

  const isLoading = subdomainsQuery.isLoading || fingerprintsQuery.isLoading || findingsQuery.isLoading;
  const isError = subdomainsQuery.isError || fingerprintsQuery.isError || findingsQuery.isError;

  return (
    <Shell>
      {/* Wider than most pages in this app (max-w-3xl/4xl elsewhere) - a 7-column table
          with real hostnames and multi-IP lists genuinely needs the room, or it forces
          the overflow-x-auto wrapper below into a horizontal scrollbar unnecessarily. */}
      <div className="w-full max-w-6xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Subdomains</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">
              {targetQuery.data?.hostname ?? "…"}
            </h1>
          </div>
          <Link
            to={`/targets/${targetId}`}
            className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan"
          >
            ← Target
          </Link>
        </div>

        {isLoading && <p className="font-mono text-sm text-slate-400">Loading subdomains…</p>}
        {isError && (
          <ErrorState
            message="Failed to load subdomain data."
            onRetry={() => {
              subdomainsQuery.refetch();
              fingerprintsQuery.refetch();
              findingsQuery.refetch();
            }}
          />
        )}

        {subdomainsQuery.data && subdomainsQuery.data.totalCount === 0 && !search && (
          <p className="font-mono text-sm text-slate-400">
            No subdomains discovered yet — run a scan to enumerate them.
          </p>
        )}

        {subdomainsQuery.data && (subdomainsQuery.data.totalCount > 0 || search) && (
          <>
            {(subdomainsTruncated || findingsTruncated) && (
              <p className="mb-3 font-mono text-xs text-neon-amber">
                {subdomainsTruncated &&
                  `Showing ${subdomainsQuery.data.items.length} of ${subdomainsQuery.data.totalCount} subdomains. `}
                {findingsTruncated &&
                  `Findings summary reflects the first ${findingsQuery.data!.items.length} of ${findingsQuery.data!.totalCount} open findings. `}
                Use the filter below to narrow results.
              </p>
            )}
            <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center">
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter by hostname…"
                className="w-full flex-1 rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none placeholder:text-muted focus:border-neon-cyan"
              />
              <button
                onClick={() => setSortByFindings((v) => !v)}
                className={`shrink-0 whitespace-nowrap rounded border px-3 py-2 font-mono text-xs uppercase tracking-widest transition ${
                  sortByFindings
                    ? "border-neon-cyan/50 text-neon-cyan"
                    : "border-slate-700 text-slate-400 hover:border-slate-500"
                }`}
              >
                Sort: {sortByFindings ? "Worst findings first ▾" : "Default order ▾"}
              </button>
            </div>
            {filtered.length > 0 && (
            <div className="overflow-x-auto rounded-lg border border-neon-cyan/20 bg-panel/60">
              <table className="w-full min-w-[720px] text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-neon-cyan/20 text-slate-400 uppercase tracking-widest">
                    <th className="px-4 py-2">Hostname</th>
                    <th className="px-4 py-2">IP addresses</th>
                    <th className="px-4 py-2">Hosting</th>
                    <th className="px-4 py-2">Tech</th>
                    <th className="px-4 py-2">Findings</th>
                    <th className="px-4 py-2">First seen</th>
                    <th className="px-4 py-2">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((sub) => {
                    const fingerprint = fingerprintsByHostname.get(sub.hostname);
                    const subFindings = findingsByHostname.get(sub.hostname) ?? [];
                    const worst = highestSeverity(subFindings.map((f) => f.severity));
                    return (
                      <tr
                        key={sub.id}
                        className="cursor-pointer border-b border-neon-cyan/10 text-slate-300 transition last:border-0 hover:bg-panel"
                        onClick={() => navigate(`/targets/${targetId}/subdomains/${encodeURIComponent(sub.hostname)}`)}
                      >
                        <td className="px-4 py-2 text-neon-cyan hover:underline">{sub.hostname}</td>
                        <td className="px-4 py-2 text-slate-400">
                          {sub.currentIpAddresses.length > 0 ? sub.currentIpAddresses.join(", ") : "—"}
                        </td>
                        <td className="px-4 py-2">
                          <HostingBadge fingerprint={fingerprint} />
                        </td>
                        <td className="px-4 py-2 text-slate-500">
                          {fingerprint && fingerprint.technologies.length > 0 ? fingerprint.technologies.length : "—"}
                        </td>
                        <td className="px-4 py-2">
                          {subFindings.length === 0 ? (
                            <span className="text-muted">clean</span>
                          ) : (
                            <span className={`font-bold ${worst ? SEVERITY_TEXT[worst] : "text-slate-400"}`}>
                              {subFindings.length} ({worst})
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2 text-slate-400">{new Date(sub.firstSeenAt).toLocaleDateString()}</td>
                        <td className="px-4 py-2 text-slate-400">{new Date(sub.lastSeenAt).toLocaleDateString()}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            )}
            {filtered.length === 0 && (
              <p className="mt-4 font-mono text-sm text-slate-400">No subdomains match “{search}”.</p>
            )}
          </>
        )}
      </div>
    </Shell>
  );
}
