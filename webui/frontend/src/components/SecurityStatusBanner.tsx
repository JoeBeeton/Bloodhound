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
 * ADMIN-only (matches the backend endpoint's own gate).
 *
 * <p>Dismissible for the current login, but not permanently: `securityBannerDismissed` lives in
 * authBridge's module-level state (see its own doc comment), not local component state - every
 * page wraps its own fresh &lt;Shell&gt;, so local state here reset on every in-app navigation, not
 * just at login, which is the exact bug a live report caught. The risk doesn't go away just
 * because someone closed the banner once, and it still stops showing entirely the moment the
 * actual misconfiguration is fixed (the two booleans below both go false).
 */
export function SecurityStatusBanner() {
  const { user, securityBannerDismissed, dismissSecurityBanner } = useAuth();
  const query = useQuery({
    queryKey: ["admin-security-status"],
    queryFn: fetchSecurityStatus,
    enabled: user?.role === "ADMIN",
    staleTime: 60_000,
  });

  if (user?.role !== "ADMIN" || !query.data || securityBannerDismissed) {
    return null;
  }

  const { jwtSigningKeyIsPlaceholder, workerApiKeyIsPlaceholder } = query.data;
  if (!jwtSigningKeyIsPlaceholder && !workerApiKeyIsPlaceholder) {
    return null;
  }

  return (
    <div className="mx-6 mb-2 rounded-lg border border-severity-critical/50 bg-severity-critical/10 px-4 py-3">
      <div className="flex items-start justify-between gap-3">
        <p className="font-mono text-xs font-bold uppercase tracking-widest text-severity-critical">
          ⚠ Security: placeholder secret{jwtSigningKeyIsPlaceholder && workerApiKeyIsPlaceholder ? "s" : ""} still in
          use
        </p>
        <button
          type="button"
          aria-label="Dismiss security warning"
          onClick={dismissSecurityBanner}
          className="shrink-0 font-mono text-xs text-severity-critical/70 transition hover:text-severity-critical"
        >
          ✕
        </button>
      </div>
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
