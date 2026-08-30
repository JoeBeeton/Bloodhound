import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import type { SecurityStatus } from "../lib/types";

async function fetchSecurityStatus(): Promise<SecurityStatus> {
  const res = await apiFetch("/api/v1/admin/security-status");
  if (!res.ok) throw new Error("Failed to load security status.");
  return res.json();
}

/**
 * A security review found that a deployment left with placeholder JWT_SIGNING_KEY/WORKER_API_KEY
 * values - meaning anyone who has ever seen this repository's .env.example can forge login tokens
 * or authenticate as a worker - previously only ever surfaced as a startup WARN in server logs. An
 * admin using the UI had no way to discover this short-of reading logs they might never look at.
 * ADMIN-only (matches the backend endpoint's own gate) and deliberately not dismissible - the risk
 * doesn't go away just because someone closed a banner once, and it stops showing entirely the
 * moment the actual misconfiguration is fixed.
 */
export function SecurityStatusBanner() {
  const { user } = useAuth();
  const query = useQuery({
    queryKey: ["admin-security-status"],
    queryFn: fetchSecurityStatus,
    enabled: user?.role === "ADMIN",
    staleTime: 60_000,
  });

  if (user?.role !== "ADMIN" || !query.data) {
    return null;
  }

  const { jwtSigningKeyIsPlaceholder, workerApiKeyIsPlaceholder } = query.data;
  if (!jwtSigningKeyIsPlaceholder && !workerApiKeyIsPlaceholder) {
    return null;
  }

  return (
    <div className="mx-6 mb-2 rounded-lg border border-severity-critical/50 bg-severity-critical/10 px-4 py-3">
      <p className="font-mono text-xs font-bold uppercase tracking-widest text-severity-critical">
        ⚠ Security: placeholder secret{jwtSigningKeyIsPlaceholder && workerApiKeyIsPlaceholder ? "s" : ""} still in use
      </p>
      <ul className="mt-1 list-inside list-disc font-mono text-xs text-slate-300">
        {jwtSigningKeyIsPlaceholder && (
          <li>
            <span className="text-severity-critical">JWT_SIGNING_KEY</span> is still the example value from
            .env.example — anyone who has seen that file can forge valid login tokens for any user in this
            deployment. Rotate it (e.g. <code className="text-neon-cyan">openssl rand -base64 48</code>) before this
            is exposed beyond a trusted local machine.
          </li>
        )}
        {workerApiKeyIsPlaceholder && (
          <li>
            <span className="text-severity-critical">WORKER_API_KEY</span> is still the example value from
            .env.example — anyone who has seen that file can authenticate as a worker and claim/report scan jobs.
            Rotate it before this is exposed beyond a trusted local machine.
          </li>
        )}
      </ul>
    </div>
  );
}
