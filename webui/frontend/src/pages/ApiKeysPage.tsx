import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CopyButton } from "../components/CopyButton";
import { ErrorState } from "../components/ErrorState";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { usePageTitle } from "../lib/usePageTitle";

export interface ApiKeySummary {
  id: string;
  label: string;
  keyPrefix: string;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  revoked: boolean;
  expired: boolean;
}

interface CreatedApiKey {
  id: string;
  label: string;
  keyPrefix: string;
  apiKey: string;
  createdAt: string;
  expiresAt: string;
}

async function fetchKeys(): Promise<ApiKeySummary[]> {
  const res = await apiFetch("/api/v1/api-keys");
  if (!res.ok) throw new Error("Failed to load API keys.");
  return res.json();
}

async function createKey(label: string, expiresInDays: number): Promise<CreatedApiKey> {
  const res = await apiFetch("/api/v1/api-keys", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label, expiresInDays }),
  });
  if (!res.ok) throw new Error("Failed to create API key.");
  return res.json();
}

async function revokeKey(id: string): Promise<void> {
  const res = await apiFetch(`/api/v1/api-keys/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to revoke API key.");
}

const DEFAULT_EXPIRY_DAYS = 90;

/** A key sitting at "Active" right up until the instant it lapses gives no warning that an
 * integration is about to break - this surfaces the same urgency the rest of the app already
 * uses amber for (RUNNING scans, near-critical scores) once expiry is close enough to act on. */
const EXPIRY_WARNING_DAYS = 14;

function daysUntil(iso: string, now: number = Date.now()): number {
  return Math.ceil((new Date(iso).getTime() - now) / (24 * 60 * 60 * 1000));
}

export function statusDisplay(key: ApiKeySummary, now: number = Date.now()): { label: string; className: string } {
  if (key.revoked) return { label: "Revoked", className: "text-slate-500" };
  if (key.expired) return { label: "Expired", className: "text-neon-amber" };
  // Trust the server's `expired` flag as authoritative for "has it lapsed" - this is purely
  // "is it lapsing soon", so a negative/zero remainder (clock skew, or expiresAt already
  // passed but the server hasn't flagged it expired yet) falls back to plain "Active" rather
  // than rendering a nonsensical negative day count.
  const remaining = daysUntil(key.expiresAt, now);
  if (remaining > 0 && remaining <= EXPIRY_WARNING_DAYS) {
    return { label: `Active · ${remaining}d left`, className: "text-neon-amber" };
  }
  return { label: "Active", className: "text-neon-cyan" };
}

/** Self-service management of the caller's own read-only external API keys - any authenticated role, not admin-gated (a key only ever grants what its creator could already see). */
export function ApiKeysPage() {
  usePageTitle("API Keys");
  const queryClient = useQueryClient();
  const [label, setLabel] = useState("");
  const [expiresInDays, setExpiresInDays] = useState(DEFAULT_EXPIRY_DAYS);
  const [created, setCreated] = useState<CreatedApiKey | null>(null);
  // Unlike a target's "Remove" (soft, reversible - see TargetsPage), revoking an API key is
  // permanent: any integration still using it breaks immediately with no undo. It previously
  // fired straight from the row's onClick with zero confirmation - a stray click on a densely
  // packed table (this row's only interactive element) silently killed a live integration.
  // Mirrors TargetsPage's own remove-target confirmation modal, the established pattern for a
  // destructive-but-self-service action in this app.
  const [pendingRevoke, setPendingRevoke] = useState<ApiKeySummary | null>(null);

  const keysQuery = useQuery({ queryKey: ["api-keys"], queryFn: fetchKeys });

  const createMutation = useMutation({
    mutationFn: () => createKey(label, expiresInDays),
    onSuccess: (key) => {
      setCreated(key);
      setLabel("");
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => revokeKey(id),
    onSuccess: () => {
      setPendingRevoke(null);
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });

  return (
    <Shell>
      <div className="mx-auto w-full max-w-4xl px-6 py-10">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Settings</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">API Keys</h1>
          </div>
          <Link to="/dashboard" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
            ← Dashboard
          </Link>
        </div>

        <div className="mb-6 rounded-lg border border-neon-cyan/20 bg-panel/60 p-5">
          <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-neon-cyan">Read-only external API</h2>
          <p className="font-mono text-xs text-slate-400">
            Keys generated here authenticate against the read-only data API documented at{" "}
            <a href="/swagger-ui.html" target="_blank" rel="noreferrer" className="text-neon-cyan hover:underline">
              /swagger-ui.html
            </a>{" "}
            - send <code className="text-neon-amber">Authorization: Bearer &lt;key&gt;</code> with each request. Keys can only
            ever read data you already have access to; they cannot create, modify, or delete anything.
          </p>
        </div>

        <div className="mb-6 rounded-lg border border-neon-magenta/20 bg-panel/60 p-5">
          <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-neon-magenta">Generate a key</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              createMutation.mutate();
            }}
            className="flex flex-wrap gap-3"
          >
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. reporting dashboard"
              // Matches CreateApiKeyRequest's own @Size(max=200).
              maxLength={200}
              required
              className="min-w-[220px] flex-1 rounded border border-slate-700 bg-void px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-neon-magenta"
            />
            <label className="flex items-center gap-2 font-mono text-xs text-slate-400">
              Expires in
              <input
                type="number"
                min={1}
                max={365}
                value={expiresInDays}
                onChange={(e) => setExpiresInDays(Number(e.target.value))}
                className="w-20 rounded border border-slate-700 bg-void px-2 py-2 text-center text-slate-200 outline-none focus:border-neon-magenta"
              />
              days
            </label>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="shrink-0 rounded bg-neon-magenta/90 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
            >
              {createMutation.isPending ? "Generating…" : "Generate key"}
            </button>
          </form>
          {createMutation.isError && (
            <p role="alert" className="mt-2 font-mono text-xs text-severity-critical">
              Failed to generate key.
            </p>
          )}
        </div>

        <div className="rounded-lg border border-slate-700 bg-panel/60 p-5">
          <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-300">Your keys</h2>
          {keysQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
          {keysQuery.isError && <ErrorState message="Failed to load API keys." onRetry={() => keysQuery.refetch()} />}
          {keysQuery.data && keysQuery.data.length === 0 && (
            <p className="font-mono text-sm text-slate-500">No API keys yet — generate one above to get started.</p>
          )}
          {keysQuery.data && keysQuery.data.length > 0 && (
            // Five columns (Label/Key/Expires/Last used/Status) genuinely don't fit a narrow
            // viewport - confirmed live, a real 375px check overflowed the whole page by 105px.
            // Scope the scroll to this table alone rather than dragging the page sideways with it.
            <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-slate-700 text-slate-500">
                  <th className="pb-2">Label</th>
                  <th className="pb-2">Key</th>
                  <th className="pb-2">Expires</th>
                  <th className="pb-2">Last used</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2" />
                </tr>
              </thead>
              <tbody>
                {keysQuery.data.map((k) => (
                  <tr key={k.id} className="border-b border-slate-800">
                    <td className="py-2 text-slate-200">{k.label}</td>
                    <td className="py-2 text-slate-500">{k.keyPrefix}…</td>
                    <td className="py-2 text-slate-400">{new Date(k.expiresAt).toLocaleDateString()}</td>
                    <td className="py-2 text-slate-400">{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : "Never"}</td>
                    <td className="py-2">
                      {(() => {
                        const status = statusDisplay(k);
                        return <span className={status.className}>{status.label}</span>;
                      })()}
                    </td>
                    <td className="py-2 text-right">
                      {!k.revoked && !k.expired && (
                        <button
                          onClick={() => setPendingRevoke(k)}
                          className="font-mono text-xs uppercase tracking-widest text-severity-critical hover:underline"
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          )}
        </div>
      </div>

      {pendingRevoke && (
        <Modal title="Revoke API key" onClose={() => setPendingRevoke(null)}>
          <p className="mb-4 text-sm text-slate-300">
            Revoke <span className="font-mono text-neon-cyan">{pendingRevoke.label}</span> ({pendingRevoke.keyPrefix}…)?
            Any integration still using this key will stop working immediately. This cannot be undone.
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
              {revokeMutation.isPending ? "Revoking…" : "Revoke key"}
            </button>
          </div>
          {revokeMutation.isError && (
            <p role="alert" className="mt-2 font-mono text-xs text-severity-critical">
              Failed to revoke key.
            </p>
          )}
        </Modal>
      )}

      {created && (
        <Modal title="API key generated" onClose={() => setCreated(null)}>
          <p className="mb-3 text-sm text-slate-300">
            Send this as <code className="text-neon-amber">Authorization: Bearer &lt;key&gt;</code> against the read-only API.
          </p>
          <div className="mb-1 flex items-center gap-2 rounded border border-neon-amber/40 bg-void/60 px-3 py-2">
            <code className="flex-1 select-all break-all font-mono text-sm text-neon-amber">{created.apiKey}</code>
            <CopyButton value={created.apiKey} />
          </div>
          <p className="mb-4 font-mono text-xs text-severity-critical">
            This key is shown once and cannot be retrieved again — copy it now.
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
