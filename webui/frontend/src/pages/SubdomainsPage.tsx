import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { HostingBadge } from "../components/TechHostingPanel";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import type { Finding, FingerprintEntry, Severity, Subdomain, Target } from "../lib/types";

async function fetchTarget(id: string): Promise<Target> {
  const res = await apiFetch(`/api/v1/targets/${id}`);
  if (!res.ok) throw new Error("Failed to load target.");
  return res.json();
}

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

async function fetchFindings(targetId: string): Promise<Finding[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/findings`);
  if (!res.ok) throw new Error("Failed to load findings.");
  return res.json();
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_TEXT: Record<Severity, string> = {
  CRITICAL: "text-severity-critical",
  HIGH: "text-severity-high",
  MEDIUM: "text-severity-medium",
  LOW: "text-severity-low",
  INFO: "text-severity-info",
};

function highestSeverity(severities: Severity[]): Severity | null {
  for (const s of SEVERITY_ORDER) {
    if (severities.includes(s)) return s;
  }
  return null;
}

/** Full subdomain inventory for a target: fingerprint + open-findings summary per subdomain, clicking through to detail. */
export function SubdomainsPage() {
  const { id } = useParams<{ id: string }>();
  const targetId = id!;
  const navigate = useNavigate();
  const [search, setSearch] = useState("");

  const targetQuery = useQuery({ queryKey: ["target", targetId], queryFn: () => fetchTarget(targetId) });
  const subdomainsQuery = useQuery({ queryKey: ["subdomains", targetId], queryFn: () => fetchSubdomains(targetId) });
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
    for (const f of findingsQuery.data ?? []) {
      const list = map.get(f.affectedAsset) ?? [];
      list.push(f);
      map.set(f.affectedAsset, list);
    }
    return map;
  }, [findingsQuery.data]);

  const filtered = (subdomainsQuery.data ?? []).filter((s) =>
    s.hostname.toLowerCase().includes(search.toLowerCase()),
  );

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

        {subdomainsQuery.data && subdomainsQuery.data.length === 0 && (
          <p className="font-mono text-sm text-slate-400">
            No subdomains discovered yet — run a scan to enumerate them.
          </p>
        )}

        {subdomainsQuery.data && subdomainsQuery.data.length > 0 && (
          <>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by hostname…"
              className="mb-4 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-neon-cyan"
            />
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
                            <span className="text-slate-600">clean</span>
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
            {filtered.length === 0 && (
              <p className="mt-4 font-mono text-sm text-slate-400">No subdomains match “{search}”.</p>
            )}
          </>
        )}
      </div>
    </Shell>
  );
}
