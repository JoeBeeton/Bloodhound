import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import type { AuthorizationStatusResponse } from "../lib/types";
import { ErrorState } from "./ErrorState";

async function fetchAuthorization(targetId: string): Promise<AuthorizationStatusResponse> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/authorization`);
  if (!res.ok) throw new Error("Failed to load authorization status.");
  return res.json();
}

async function authorize(targetId: string, attestationText: string): Promise<AuthorizationStatusResponse> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/authorization`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attestationText }),
  });
  if (!res.ok) throw new Error("Failed to record authorization.");
  return res.json();
}

async function revoke(targetId: string): Promise<AuthorizationStatusResponse> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/authorization`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to revoke authorization.");
  return res.json();
}

/**
 * The gate Tier 2 active scanning (deep port scan, and OWASP ZAP once it lands)
 * checks server-side before it will ever touch a target - see
 * TargetAuthorizationController/TargetController#deepScanNow. Authorizing is
 * deliberately not a single click: it requires typing a real attestation
 * statement, since it's a logged, auditable claim of authorization to
 * actively scan someone else's - or your own - infrastructure.
 */
export function AuthorizationPanel({ targetId }: { targetId: string }) {
  const queryClient = useQueryClient();
  const [attestationText, setAttestationText] = useState("");

  const authQuery = useQuery({
    queryKey: ["authorization", targetId],
    queryFn: () => fetchAuthorization(targetId),
  });

  const authorizeMutation = useMutation({
    mutationFn: () => authorize(targetId, attestationText),
    onSuccess: () => {
      setAttestationText("");
      queryClient.invalidateQueries({ queryKey: ["authorization", targetId] });
      queryClient.invalidateQueries({ queryKey: ["target", targetId] });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: () => revoke(targetId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["authorization", targetId] });
      queryClient.invalidateQueries({ queryKey: ["target", targetId] });
    },
  });

  if (authQuery.isLoading) {
    return <p className="font-mono text-sm text-slate-400">Loading authorization status…</p>;
  }
  if (authQuery.isError) {
    return <ErrorState message="Failed to load authorization status." onRetry={() => authQuery.refetch()} />;
  }

  const status = authQuery.data!.authorizationStatus;
  const current = authQuery.data!.history.find((entry) => entry.revokedAt === null);
  const isAuthorized = status === "AUTHORIZED";

  return (
    <div
      className={`rounded-lg border p-4 ${isAuthorized ? "border-neon-cyan/40 bg-neon-cyan/5" : "border-neon-magenta/30 bg-panel/60"}`}
    >
      <div className="mb-2 flex items-center gap-2">
        <span className="rounded border border-neon-amber/50 px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-neon-amber">
          Tier 2
        </span>
        <span
          className={`font-mono text-xs font-bold uppercase tracking-widest ${isAuthorized ? "text-neon-cyan" : "text-slate-400"}`}
        >
          {isAuthorized ? "Authorized for active scanning" : "Not authorized for active scanning"}
        </span>
      </div>

      {isAuthorized && current && (
        <p className="mb-3 font-mono text-xs text-slate-400">
          Authorized {new Date(current.authorizedAt).toLocaleString()} — "{current.attestationText}"
        </p>
      )}
      {!isAuthorized && (
        <p className="mb-3 text-sm text-slate-400">
          Deep scans (full port range, service detection, NSE scripts) are meaningfully more intrusive than the
          passive Tier 1 checks and only ever run against targets your organization has explicitly attested
          authorization for.
        </p>
      )}

      {isAuthorized ? (
        <button
          onClick={() => revokeMutation.mutate()}
          disabled={revokeMutation.isPending}
          className="rounded border border-severity-critical/50 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10 disabled:opacity-40"
        >
          {revokeMutation.isPending ? "Revoking…" : "Revoke authorization"}
        </button>
      ) : (
        <div className="flex flex-col gap-2">
          <textarea
            value={attestationText}
            onChange={(e) => setAttestationText(e.target.value)}
            placeholder='e.g. "I confirm we own/have written permission to actively scan this asset."'
            rows={2}
            className="w-full rounded border border-neon-cyan/20 bg-void/60 px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-neon-cyan/60 focus:outline-none"
          />
          <button
            onClick={() => authorizeMutation.mutate()}
            disabled={authorizeMutation.isPending || attestationText.trim().length === 0}
            className="self-start rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10 disabled:opacity-40"
          >
            {authorizeMutation.isPending ? "Recording…" : "Authorize for deep scanning"}
          </button>
        </div>
      )}
      {(authorizeMutation.isError || revokeMutation.isError) && (
        <p className="mt-2 font-mono text-xs text-severity-critical">Action failed — please try again.</p>
      )}
    </div>
  );
}
