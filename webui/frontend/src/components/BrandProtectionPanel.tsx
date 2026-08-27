import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import { ErrorState } from "./ErrorState";
import { ScreenshotThumbnail } from "./ScreenshotThumbnail";
import type { TyposquatListResponse } from "../lib/types";

async function fetchTyposquats(targetId: string): Promise<TyposquatListResponse> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/typosquats`);
  if (!res.ok) throw new Error("Failed to load brand-protection data.");
  return res.json();
}

function humanizePermutationType(type: string): string {
  return type.toLowerCase().replace(/_/g, " ");
}

/** Registered lookalike domains for a target's own root hostname — typosquat/brand-impersonation monitoring. A clean/empty result (no lookalikes registered) is the common case and reads as reassuring, not broken. */
export function BrandProtectionPanel({
  targetId,
  realDomainHostname,
}: {
  targetId: string;
  /** For the real-domain screenshot's label and alt text - the candidate list itself doesn't carry the target's own hostname. */
  realDomainHostname: string;
}) {
  const query = useQuery({
    queryKey: ["typosquats", targetId],
    queryFn: () => fetchTyposquats(targetId),
  });

  if (query.isLoading) {
    return <p className="font-mono text-sm text-slate-400">Loading brand-protection data…</p>;
  }
  if (query.isError) {
    return <ErrorState message="Failed to load brand-protection data." onRetry={() => query.refetch()} />;
  }

  const candidates = query.data?.candidates ?? [];
  if (candidates.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No registered lookalike domains detected — nothing to review right now.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {query.data?.realDomainHasScreenshot && (
        <div className="flex items-center gap-3 rounded-lg border border-neon-cyan/30 bg-panel/60 p-3">
          <ScreenshotThumbnail
            src={`/api/v1/targets/${targetId}/typosquats/real-domain-screenshot`}
            alt={`Screenshot of ${realDomainHostname} (the real domain)`}
            size="large"
          />
          <div>
            <p className="font-mono text-[10px] uppercase tracking-widest text-neon-cyan">Real domain</p>
            <p className="font-mono text-sm text-slate-200">{realDomainHostname}</p>
            <p className="font-mono text-[11px] text-slate-500">
              Every "visual match" percentage below is a comparison against this screenshot.
            </p>
          </div>
        </div>
      )}

      <div className="overflow-x-auto rounded-lg border border-severity-high/20 bg-panel/60">
        <table className="w-full text-left font-mono text-xs">
          <thead>
            <tr className="border-b border-severity-high/20 text-slate-400 uppercase tracking-widest">
              <th className="px-3 py-2">Preview</th>
              <th className="px-3 py-2">Domain</th>
              <th className="px-3 py-2">Technique</th>
              <th className="px-3 py-2">Visual match</th>
              <th className="px-3 py-2">Resolved IP</th>
              <th className="px-3 py-2">Registered</th>
              <th className="px-3 py-2">First seen</th>
            </tr>
          </thead>
          <tbody>
            {candidates.map((c) => (
              <tr key={c.id} className="border-b border-slate-700/40 last:border-0">
                <td className="px-3 py-2">
                  {c.hasScreenshot ? (
                    <ScreenshotThumbnail
                      src={`/api/v1/targets/${targetId}/typosquats/${c.id}/screenshot`}
                      alt={`Screenshot of ${c.candidateDomain}`}
                    />
                  ) : (
                    <span className="font-mono text-[10px] text-slate-600">—</span>
                  )}
                </td>
                <td className="px-3 py-2 text-severity-high">{c.candidateDomain}</td>
                <td className="px-3 py-2 text-slate-300 normal-case">{humanizePermutationType(c.permutationType)}</td>
                <td className="px-3 py-2">
                  {c.visualSimilarityPercent === null ? (
                    <span className="text-slate-600">—</span>
                  ) : (
                    <span className={c.visualSimilarityPercent >= 80 ? "font-bold text-severity-critical" : "text-slate-400"}>
                      {c.visualSimilarityPercent}%
                    </span>
                  )}
                </td>
                <td className="px-3 py-2 text-slate-400">{c.resolvedIp ?? "—"}</td>
                <td className="px-3 py-2 text-slate-400">
                  {c.registrationDate ? new Date(c.registrationDate).toLocaleDateString() : "—"}
                </td>
                <td className="px-3 py-2 text-slate-500">{new Date(c.firstSeenAt).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
