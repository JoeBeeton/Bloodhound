import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { ErrorState } from "../components/ErrorState";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch, readErrorMessage } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import { usePageTitle } from "../lib/usePageTitle";
import { useUnsavedChangesWarning } from "../lib/useUnsavedChangesWarning";

/**
 * Unlike Slack's webhookUrlMasked (see AdminSlackPage), there is no partial preview of the
 * token here at all - GithubSecretSearchIntegrationController's own javadoc explains why: the
 * token is encrypted at rest, and decrypting it on every page load just to redact most of the
 * result would be a real cost for no real benefit. "configured since X" is enough for an admin
 * to know a token is set without ever seeing any part of its value.
 */
interface GithubSecretScanIntegration {
  enabled: boolean;
  updatedAt: string;
}

interface SaveIntegrationInput {
  /** Blank means "leave the currently-stored token unchanged" - see AdminGithubSecretScanPage's save handler. */
  token: string;
  enabled: boolean;
}

async function fetchIntegration(orgId: string): Promise<GithubSecretScanIntegration | null> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/github-secret-search-integration`);
  if (res.status === 204) return null;
  if (!res.ok) throw new Error("Failed to load GitHub secret-scan integration.");
  return res.json();
}

async function saveIntegration(orgId: string, body: SaveIntegrationInput): Promise<GithubSecretScanIntegration> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/github-secret-search-integration`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readErrorMessage(res, "Failed to save GitHub secret-scan integration."));
  return res.json();
}

async function deleteIntegration(orgId: string): Promise<void> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/github-secret-search-integration`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to remove GitHub secret-scan integration.");
}

const MIN_TOKEN_LENGTH = 20;

export function AdminGithubSecretScanPage() {
  usePageTitle("GitHub Secret Scan");
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const queryClient = useQueryClient();

  // The server never sends the real token back at all (see the interface's own comment) -
  // token here is only ever what the admin is actively typing to SET or REPLACE it, never a
  // round-tripped value from the server. isEditingToken tracks whether that input is shown:
  // once an integration exists, a plain "configured" line displays until "Replace" is clicked,
  // so a save that only toggles "enabled" can't accidentally blank out a token the frontend was
  // never given the real value of in the first place.
  const [token, setToken] = useState("");
  const [isEditingToken, setIsEditingToken] = useState(true);
  const [enabled, setEnabled] = useState(true);
  // Same hydratedFrom-timing fix as AdminSlackPage's own useUnsavedChangesWarning gate - see its
  // comment for the one-render window this closes.
  const [hydratedFrom, setHydratedFrom] = useState<GithubSecretScanIntegration | null | undefined>(undefined);
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const query = useQuery({
    queryKey: ["admin-github-secret-scan-integration", orgId],
    queryFn: () => fetchIntegration(orgId),
    enabled: !!orgId,
  });

  useEffect(() => {
    if (query.data) {
      setToken("");
      setIsEditingToken(false);
      setEnabled(query.data.enabled);
    } else if (query.data === null) {
      setIsEditingToken(true);
    }
    setHydratedFrom(query.data);
  }, [query.data]);

  // A freshly-typed token is the one thing here that's genuinely painful to lose - it isn't
  // retrievable by reopening this page (the server never round-trips it), and GitHub itself has
  // no "show me the token I already made" screen once the creation page is left - regenerating
  // one means creating a brand new personal access token from scratch.
  const hasUnsavedChanges =
    (isEditingToken && token.trim() !== "") ||
    (hydratedFrom === query.data && query.data != null && enabled !== query.data.enabled);
  useUnsavedChangesWarning(hasUnsavedChanges);

  const saveMutation = useMutation({
    // Blank token (not currently editing it) tells the server "leave the stored token
    // unchanged" - see GithubSecretSearchIntegrationController#save's javadoc for the other
    // half of this.
    mutationFn: () => saveIntegration(orgId, { token: isEditingToken ? token : "", enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-github-secret-scan-integration", orgId] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteIntegration(orgId),
    onSuccess: () => {
      setConfirmingDelete(false);
      setToken("");
      setIsEditingToken(true);
      queryClient.invalidateQueries({ queryKey: ["admin-github-secret-scan-integration", orgId] });
    },
  });

  const tokenLooksValid = token === "" || token.trim().length >= MIN_TOKEN_LENGTH;
  // While editing, a plausible-length token is required (blank would be read as "leave
  // unchanged" server-side, which isn't what a form the admin is actively filling in should do).
  const canSubmit = isEditingToken ? tokenLooksValid && token.trim() !== "" : true;

  return (
    <Shell>
      <div className="mx-auto w-full max-w-4xl px-6 py-10">
        <div className="mb-2">
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
          <h1 className="font-display text-2xl font-bold text-neon-cyan">GitHub Secret Scan</h1>
        </div>
        <AdminSubNav />

        {query.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
        {query.isError && (
          <ErrorState message="Failed to load GitHub secret-scan integration." onRetry={() => query.refetch()} />
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            saveMutation.mutate();
          }}
          className="mb-6 rounded-lg border border-neon-cyan/20 bg-panel/60 p-5"
        >
          <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-neon-cyan">GitHub token</h2>
          <p className="mb-3 font-mono text-xs text-slate-400">
            Create a personal access token with public code-search access and paste it here. Used to search
            public GitHub repositories for this org's own domains, so any live-looking secret found alongside
            them can be flagged - the token itself is encrypted at rest and never shown again once saved.
          </p>

          {!isEditingToken && query.data ? (
            <div className="mb-2 flex items-center gap-3 rounded border border-slate-700 bg-void px-3 py-2">
              <span className="flex-1 font-mono text-xs text-slate-400">
                Configured · last updated {new Date(query.data.updatedAt).toLocaleString()}
              </span>
              <button
                type="button"
                onClick={() => setIsEditingToken(true)}
                className="shrink-0 font-mono text-[11px] uppercase tracking-widest text-neon-cyan hover:underline"
              >
                Replace
              </button>
            </div>
          ) : (
            <>
              <input
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="ghp_… or github_pat_…"
                autoFocus={query.data != null}
                required
                className={`mb-1 w-full rounded border bg-void px-3 py-2 font-mono text-xs text-slate-200 outline-none ${
                  tokenLooksValid ? "border-slate-700 focus:border-neon-cyan" : "border-severity-critical"
                }`}
              />
              {!tokenLooksValid && (
                <p className="mb-2 font-mono text-[11px] text-severity-critical">
                  Too short to be a real GitHub personal access token.
                </p>
              )}
              {query.data && (
                <button
                  type="button"
                  onClick={() => {
                    setIsEditingToken(false);
                    setToken("");
                  }}
                  className="mb-2 font-mono text-[11px] uppercase tracking-widest text-slate-400 hover:text-neon-cyan"
                >
                  Cancel
                </button>
              )}
            </>
          )}

          <label className="mt-3 flex items-center gap-2 font-mono text-xs text-slate-300">
            <input className="checkbox-cyber" type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enabled
          </label>

          <div className="mt-5 flex items-center gap-3">
            <button
              type="submit"
              disabled={saveMutation.isPending || !canSubmit}
              className="rounded bg-neon-magenta/90 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
            >
              {saveMutation.isPending ? "Saving…" : "Save"}
            </button>
            {query.data && (
              <button
                type="button"
                onClick={() => setConfirmingDelete(true)}
                className="font-mono text-xs uppercase tracking-widest text-severity-critical hover:underline"
              >
                Remove integration
              </button>
            )}
          </div>
          {hasUnsavedChanges && !saveMutation.isPending && (
            <p className="mt-2 font-mono text-xs text-neon-amber">Unsaved changes.</p>
          )}
          {saveMutation.isError && (
            <p role="alert" className="mt-2 font-mono text-xs text-severity-critical">
              {(saveMutation.error as Error)?.message ?? "Failed to save."}
            </p>
          )}
        </form>
      </div>

      {confirmingDelete && (
        <Modal title="Remove GitHub secret-scan integration" onClose={() => setConfirmingDelete(false)}>
          <p className="mb-4 text-sm text-slate-300">
            Remove this integration? The GITHUB_SECRET_SEARCH check stops running on future deep scans, and
            the token isn't retrievable once removed - restoring this later means generating a new personal
            access token in GitHub and pasting it in again from scratch.
          </p>
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setConfirmingDelete(false)}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
            >
              Cancel
            </button>
            <button
              onClick={() => deleteMutation.mutate()}
              disabled={deleteMutation.isPending}
              className="rounded border border-severity-critical/50 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10 disabled:opacity-40"
            >
              {deleteMutation.isPending ? "Removing…" : "Remove integration"}
            </button>
          </div>
          {deleteMutation.isError && (
            <p role="alert" className="mt-2 font-mono text-xs text-severity-critical">
              Failed to remove the integration. Try again.
            </p>
          )}
        </Modal>
      )}
    </Shell>
  );
}
