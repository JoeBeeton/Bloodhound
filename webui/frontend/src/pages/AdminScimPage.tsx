import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { CopyButton } from "../components/CopyButton";
import { ErrorState } from "../components/ErrorState";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import { usePageTitle } from "../lib/usePageTitle";

interface ScimTokenSummary {
  id: string;
  label: string;
  createdAt: string;
  revokedAt: string | null;
  /** Null means it never expires - unlike API keys, that's a deliberate, supported choice for a continuous directory-sync credential, not a gap. */
  expiresAt: string | null;
  expired: boolean;
}

interface CreatedToken {
  id: string;
  label: string;
  token: string;
  createdAt: string;
  expiresAt: string | null;
}

interface ScimTokensResponse {
  scimBaseUrl: string;
  tokens: ScimTokenSummary[];
}

/** Same urgency treatment ApiKeysPage already gives a lapsing key - amber once expiry is close enough to act on, but only ever shown for a token that has an expiry at all. */
const EXPIRY_WARNING_DAYS = 14;

function daysUntil(iso: string, now: number = Date.now()): number {
  return Math.ceil((new Date(iso).getTime() - now) / (24 * 60 * 60 * 1000));
}

export function statusDisplay(token: ScimTokenSummary, now: number = Date.now()): { label: string; className: string } {
  if (token.revokedAt) return { label: "Revoked", className: "text-slate-500" };
  if (token.expired) return { label: "Expired", className: "text-neon-amber" };
  if (!token.expiresAt) return { label: "Active · never expires", className: "text-neon-cyan" };
  const remaining = daysUntil(token.expiresAt, now);
  if (remaining > 0 && remaining <= EXPIRY_WARNING_DAYS) {
    return { label: `Active · ${remaining}d left`, className: "text-neon-amber" };
  }
  return { label: "Active", className: "text-neon-cyan" };
}

async function fetchTokens(orgId: string): Promise<ScimTokensResponse> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/scim-tokens`);
  if (!res.ok) throw new Error("Failed to load SCIM tokens.");
  return res.json();
}

async function createToken(orgId: string, label: string, expiresInDays: number | null): Promise<CreatedToken> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/scim-tokens`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label, expiresInDays }),
  });
  if (!res.ok) throw new Error("Failed to create SCIM token.");
  return res.json();
}

async function revokeToken(orgId: string, tokenId: string): Promise<void> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/scim-tokens/${tokenId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to revoke SCIM token.");
}

function MetadataField({ label, value }: { label: string; value: string }) {
  return (
    <div className="mb-3">
      <p className="mb-1 font-mono text-[11px] uppercase tracking-widest text-slate-400">{label}</p>
      <code className="block break-all rounded border border-slate-700 bg-void px-3 py-2 font-mono text-xs text-neon-cyan">{value}</code>
    </div>
  );
}

export function AdminScimPage() {
  usePageTitle("SCIM Provisioning");
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const queryClient = useQueryClient();
  const [label, setLabel] = useState("");
  // String, not number: "" is the meaningful "never expires" default (unlike ApiKeysPage, which
  // always has a numeric DEFAULT_EXPIRY_DAYS) - a continuous directory-sync integration shouldn't
  // get an unannounced expiry forced on it just because a numeric input needs *some* value.
  const [expiresInDays, setExpiresInDays] = useState("");
  const [created, setCreated] = useState<CreatedToken | null>(null);
  // Revoking cuts off the IdP's ability to push provisioning events immediately - a stray click
  // on this table's only per-row control could otherwise silently break an org's live user
  // provisioning. Mirrors ApiKeysPage's own pendingRevoke confirmation modal, the established
  // pattern for this exact "destructive-but-self-service, one click away" shape in this app -
  // a security/AppSec review found this page was the one credential-revoke flow that never
  // adopted it and still fired straight from onClick.
  const [pendingRevoke, setPendingRevoke] = useState<ScimTokenSummary | null>(null);

  const tokensQuery = useQuery({ queryKey: ["admin-scim-tokens", orgId], queryFn: () => fetchTokens(orgId), enabled: !!orgId });

  const createMutation = useMutation({
    mutationFn: () => createToken(orgId, label, expiresInDays === "" ? null : Number(expiresInDays)),
    onSuccess: (token) => {
      setCreated(token);
      setLabel("");
      setExpiresInDays("");
      queryClient.invalidateQueries({ queryKey: ["admin-scim-tokens", orgId] });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (tokenId: string) => revokeToken(orgId, tokenId),
    onSuccess: () => {
      setPendingRevoke(null);
      queryClient.invalidateQueries({ queryKey: ["admin-scim-tokens", orgId] });
    },
  });

  return (
    <Shell>
      <div className="mx-auto w-full max-w-4xl px-6 py-10">
        <div className="mb-2">
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
          <h1 className="font-display text-2xl font-bold text-neon-cyan">SCIM Provisioning</h1>
        </div>
        <AdminSubNav />

        <div className="mb-6 rounded-lg border border-neon-cyan/20 bg-panel/60 p-5">
          <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-neon-cyan">Give this to your identity provider</h2>
          <p className="mb-4 font-mono text-xs text-slate-400">
            Paste this base URL plus a generated bearer token below into your IdP's SCIM provisioning
            configuration (Okta, Azure AD, etc.) to let it push user create/update/deactivate events to Bloodhound.
          </p>
          {tokensQuery.data && <MetadataField label="SCIM Base URL" value={tokensQuery.data.scimBaseUrl} />}
        </div>

        <div className="mb-6 rounded-lg border border-neon-magenta/20 bg-panel/60 p-5">
          <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-neon-magenta">Generate a bearer token</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              createMutation.mutate();
            }}
            // flex-wrap: the input's placeholder-driven intrinsic width plus the button
            // together overflowed a narrow viewport (a flex-1 child doesn't shrink below its
            // own content width unless it wraps or gets min-w-0) - confirmed live, +44px on a
            // real 375px check. Wrapping drops the button to its own line instead.
            className="flex flex-wrap gap-3"
          >
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Okta production"
              required
              className="min-w-0 flex-1 rounded border border-slate-700 bg-void px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-neon-magenta"
            />
            <label className="flex items-center gap-2 font-mono text-xs text-slate-400">
              Expires in
              <input
                type="number"
                min={1}
                max={3650}
                value={expiresInDays}
                onChange={(e) => setExpiresInDays(e.target.value)}
                placeholder="never"
                title="Leave blank for a token that never expires - the right default for a continuous directory-sync integration."
                className="w-20 rounded border border-slate-700 bg-void px-2 py-2 text-center text-slate-200 outline-none focus:border-neon-magenta"
              />
              days
            </label>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="shrink-0 rounded bg-neon-magenta/90 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
            >
              {createMutation.isPending ? "Generating…" : "Generate token"}
            </button>
          </form>
          <p className="mt-2 font-mono text-[11px] text-slate-500">
            Leave "Expires in" blank for a token that never expires — the right default for an ongoing SCIM sync.
            Set a value if your compliance posture requires bounded-lifetime credentials.
          </p>
          {createMutation.isError && <p className="mt-2 font-mono text-xs text-severity-critical">Failed to generate token.</p>}
        </div>

        <div className="rounded-lg border border-slate-700 bg-panel/60 p-5">
          <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-300">Tokens</h2>
          {tokensQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
          {tokensQuery.isError && <ErrorState message="Failed to load SCIM tokens." onRetry={() => tokensQuery.refetch()} />}
          {tokensQuery.data && tokensQuery.data.tokens.length === 0 && (
            <p className="font-mono text-sm text-slate-500">No SCIM tokens yet — generate one above to get started.</p>
          )}
          {tokensQuery.data && tokensQuery.data.tokens.length > 0 && (
            // overflow-x-auto + min-w on the table itself, not the page - the same fix
            // ApiKeysPage's own table already got (see its comment: "a real 375px check
            // overflowed the whole page by 105px"). This table never got the equivalent
            // treatment despite the exact same shape (a free-text Label column plus a
            // full-locale-datetime column can't shrink below their content width) - a security/
            // UX review found this was the one table left dragging the whole page sideways on a
            // narrow viewport instead of scrolling on its own.
            <div className="overflow-x-auto">
            <table className="w-full min-w-[480px] text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-slate-700 text-slate-500">
                  <th className="pb-2">Label</th>
                  <th className="pb-2">Created</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2" />
                </tr>
              </thead>
              <tbody>
                {tokensQuery.data.tokens.map((t) => {
                  const status = statusDisplay(t);
                  return (
                    <tr key={t.id} className="border-b border-slate-800">
                      <td className="py-2 text-slate-200">{t.label}</td>
                      <td className="py-2 text-slate-400">{new Date(t.createdAt).toLocaleString()}</td>
                      <td className="py-2">
                        <span className={status.className} title={t.expiresAt ? `Expires ${new Date(t.expiresAt).toLocaleString()}` : "Never expires"}>
                          {status.label}
                        </span>
                      </td>
                      <td className="py-2 text-right">
                        {!t.revokedAt && (
                          <button
                            onClick={() => setPendingRevoke(t)}
                            className="font-mono text-xs uppercase tracking-widest text-severity-critical hover:underline"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            </div>
          )}
        </div>
      </div>

      {pendingRevoke && (
        <Modal title="Revoke SCIM token" onClose={() => setPendingRevoke(null)}>
          <p className="mb-4 text-sm text-slate-300">
            Revoke <span className="font-mono text-neon-cyan">{pendingRevoke.label}</span>? Your identity provider
            will immediately lose the ability to push user provisioning events with this token. This cannot be
            undone.
          </p>
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setPendingRevoke(null)}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
            >
              Cancel
            </button>
            <button
              onClick={() => revokeMutation.mutate(pendingRevoke.id)}
              disabled={revokeMutation.isPending}
              className="rounded border border-severity-critical/50 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10 disabled:opacity-40"
            >
              {revokeMutation.isPending ? "Revoking…" : "Revoke token"}
            </button>
          </div>
          {revokeMutation.isError && (
            <p className="mt-2 font-mono text-xs text-severity-critical">Failed to revoke token. Try again.</p>
          )}
        </Modal>
      )}

      {created && (
        <Modal title="SCIM token generated" onClose={() => setCreated(null)}>
          <p className="mb-3 text-sm text-slate-300">
            Paste this bearer token into your IdP's SCIM configuration alongside the base URL above.
            {created.expiresAt ? (
              <> It expires {new Date(created.expiresAt).toLocaleDateString()}.</>
            ) : (
              <> It never expires — remember to revoke it yourself if this integration is ever decommissioned.</>
            )}
          </p>
          <div className="mb-1 flex items-center gap-2 rounded border border-neon-amber/40 bg-void/60 px-3 py-2">
            <code className="flex-1 select-all break-all font-mono text-sm text-neon-amber">{created.token}</code>
            <CopyButton value={created.token} />
          </div>
          <p className="mb-4 font-mono text-xs text-severity-critical">
            This token is shown once and cannot be retrieved again — copy it now.
          </p>
          <button
            onClick={() => setCreated(null)}
            className="w-full rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10"
          >
            Done
          </button>
        </Modal>
      )}
    </Shell>
  );
}
