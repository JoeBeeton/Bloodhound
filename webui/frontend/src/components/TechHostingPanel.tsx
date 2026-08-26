import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import { ErrorState } from "./ErrorState";
import type { FingerprintEntry } from "../lib/types";

async function fetchFingerprints(targetId: string): Promise<FingerprintEntry[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/fingerprints`);
  if (!res.ok) throw new Error("Failed to load fingerprint data.");
  return res.json();
}

// Rough grouping for badge color only - not exhaustive, just needs to look
// intentional rather than every category rendering identically.
const CATEGORY_STYLES: Record<string, string> = {
  CMS: "border-neon-magenta/40 text-neon-magenta",
  FRAMEWORK: "border-neon-magenta/40 text-neon-magenta",
  JS_LIBRARY: "border-neon-cyan/40 text-neon-cyan",
  CDN: "border-neon-amber/40 text-neon-amber",
  ANALYTICS: "border-neon-amber/40 text-neon-amber",
  WEB_SERVER: "border-slate-500/40 text-slate-300",
  LANGUAGE_RUNTIME: "border-slate-500/40 text-slate-300",
};

function TechBadge({ name, category, version }: { name: string; category: string; version?: string | null }) {
  const style = CATEGORY_STYLES[category] ?? "border-slate-500/40 text-slate-300";
  return (
    <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest ${style}`}>
      {name}
      {version && <span className="ml-1 text-slate-400 normal-case">{version}</span>}
    </span>
  );
}

export function HostingBadge({ fingerprint }: { fingerprint: FingerprintEntry | undefined }) {
  if (!fingerprint || !fingerprint.hostingProvider) return <span className="text-slate-600">—</span>;
  return (
    <span
      title={fingerprint.hostingAsn ? `${fingerprint.hostingAsn} · ${fingerprint.hostingAsnOrg}` : undefined}
      className="rounded border border-neon-cyan/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-neon-cyan"
    >
      {fingerprint.hostingProvider}
    </span>
  );
}

/** Technology stack + hosting provider for one already-fetched fingerprint - the reusable presentational half of TechHostingPanel, for any hostname (root or a specific subdomain), used by the subdomain detail view. */
export function FingerprintPanel({ fingerprint }: { fingerprint: FingerprintEntry | undefined }) {
  if (!fingerprint) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No fingerprint data yet — run a scan to detect the technology stack and hosting provider.
      </p>
    );
  }
  return (
    <div className="rounded-lg border border-neon-cyan/20 bg-panel/60 p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs uppercase tracking-widest text-slate-400">Hosting:</span>
        <HostingBadge fingerprint={fingerprint} />
        {fingerprint.hostingAsn && (
          <span className="font-mono text-[11px] text-slate-500">
            {fingerprint.hostingAsn}
            {fingerprint.hostingAsnOrg ? ` · ${fingerprint.hostingAsnOrg}` : ""}
          </span>
        )}
      </div>
      {fingerprint.technologies.length === 0 ? (
        <p className="font-mono text-sm text-slate-400">No technologies detected from passive signals.</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {fingerprint.technologies.map((t) => (
            <TechBadge key={t.name} name={t.name} category={t.category} version={t.version} />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Root-domain technology stack + hosting provider. Also exposes the full
 * per-hostname list via onLoaded so the subdomains table can show a compact
 * per-row hosting badge without a second fetch.
 */
export function TechHostingPanel({
  targetId,
  rootHostname,
  onLoaded,
}: {
  targetId: string;
  rootHostname: string | undefined;
  onLoaded?: (byHostname: Map<string, FingerprintEntry>) => void;
}) {
  const query = useQuery({
    queryKey: ["fingerprints", targetId],
    queryFn: () => fetchFingerprints(targetId),
  });

  // Runs only when the fetched data actually changes, not on every render -
  // calling onLoaded unconditionally during render would hand the parent a
  // freshly-constructed Map each time, which (since it's never reference-equal
  // to the previous one) would trigger an immediate re-render loop.
  useEffect(() => {
    if (query.data && onLoaded) {
      onLoaded(new Map(query.data.map((f) => [f.hostname, f])));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.data]);

  if (query.isLoading) {
    return <p className="font-mono text-sm text-slate-400">Loading technology &amp; hosting data…</p>;
  }
  if (query.isError) {
    return <ErrorState message="Failed to load technology &amp; hosting data." onRetry={() => query.refetch()} />;
  }

  const root = query.data?.find((f) => f.hostname === rootHostname);
  return <FingerprintPanel fingerprint={root} />;
}
