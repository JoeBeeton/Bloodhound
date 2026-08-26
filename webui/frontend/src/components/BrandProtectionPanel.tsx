import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import { ErrorState } from "./ErrorState";
import type { TyposquatCandidate } from "../lib/types";

async function fetchTyposquats(targetId: string): Promise<TyposquatCandidate[]> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/typosquats`);
  if (!res.ok) throw new Error("Failed to load brand-protection data.");
  return res.json();
}

function humanizePermutationType(type: string): string {
  return type.toLowerCase().replace(/_/g, " ");
}

/** Registered lookalike domains for a target's own root hostname — typosquat/brand-impersonation monitoring. A clean/empty result (no lookalikes registered) is the common case and reads as reassuring, not broken. */
export function BrandProtectionPanel({ targetId }: { targetId: string }) {
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

  const candidates = query.data ?? [];
  if (candidates.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No registered lookalike domains detected — nothing to review right now.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-severity-high/20 bg-panel/60">
      <table className="w-full text-left font-mono text-xs">
        <thead>
          <tr className="border-b border-severity-high/20 text-slate-400 uppercase tracking-widest">
            <th className="px-3 py-2">Domain</th>
            <th className="px-3 py-2">Technique</th>
            <th className="px-3 py-2">Resolved IP</th>
            <th className="px-3 py-2">Registered</th>
            <th className="px-3 py-2">First seen</th>
          </tr>
        </thead>
        <tbody>
          {candidates.map((c) => (
            <tr key={c.id} className="border-b border-slate-700/40 last:border-0">
              <td className="px-3 py-2 text-severity-high">{c.candidateDomain}</td>
              <td className="px-3 py-2 text-slate-300 normal-case">{humanizePermutationType(c.permutationType)}</td>
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
  );
}
