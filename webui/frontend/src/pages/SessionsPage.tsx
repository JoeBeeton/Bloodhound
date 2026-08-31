import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch, readErrorMessage } from "../lib/apiClient";
import { usePageTitle } from "../lib/usePageTitle";

export interface SessionSummary {
  id: string;
  sessionStartedAt: string;
  createdAt: string;
  expiresAt: string;
}

async function fetchSessions(): Promise<SessionSummary[]> {
  const res = await apiFetch("/api/v1/users/me/sessions");
  if (!res.ok) throw new Error("Failed to load sessions.");
  return res.json();
}

async function endSession(id: string): Promise<void> {
  const res = await apiFetch(`/api/v1/users/me/sessions/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error(await readErrorMessage(res, "Failed to end session."));
}

/**
 * The detailed counterpart to ChangePasswordModal's own "N other sessions" count + bulk
 * "log out other devices" action - that one is a fast path for "something feels off, kill
 * everything else", this is for recognizing and ending one specific stale session without also
 * signing out every other device. Deliberately no device/browser/IP column - refresh_tokens
 * doesn't capture any of that today (see RefreshTokenRepository#listActiveForUser's own comment
 * server-side), so sessionStartedAt is the only thing here that can help someone tell rows apart;
 * a future iteration that captures User-Agent at issuance would make this meaningfully better.
 */
export function SessionsPage() {
  usePageTitle("Active Sessions");
  const queryClient = useQueryClient();
  const [pendingRevoke, setPendingRevoke] = useState<SessionSummary | null>(null);

  const sessionsQuery = useQuery({ queryKey: ["active-sessions"], queryFn: fetchSessions });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => endSession(id),
    onSuccess: () => {
      setPendingRevoke(null);
      queryClient.invalidateQueries({ queryKey: ["active-sessions"] });
      // The count shown inside ChangePasswordModal (a separate query) would otherwise go stale
      // until that modal's own next mount.
      queryClient.invalidateQueries({ queryKey: ["active-session-count"] });
    },
  });

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleString();
  }

  return (
    <Shell>
      <div className="mx-auto w-full max-w-3xl px-6 py-10">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Settings</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">Active Sessions</h1>
          </div>
          <Link to="/dashboard" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
            ← Dashboard
          </Link>
        </div>

        <div className="mb-6 rounded-lg border border-neon-cyan/20 bg-panel/60 p-5">
          <p className="font-mono text-xs text-slate-400">
            Every device and browser currently signed in to your account, one row per session. End a session you don't
            recognize, or one you're done with, without signing out everywhere else - to do that instead, use{" "}
            <span className="text-slate-300">Change password → Active sessions</span>.
          </p>
        </div>

        <div className="rounded-lg border border-slate-700 bg-panel/60 p-5">
          {sessionsQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
          {sessionsQuery.isError && <ErrorState message="Failed to load sessions." onRetry={() => sessionsQuery.refetch()} />}
          {sessionsQuery.data && sessionsQuery.data.length === 0 && (
            <p className="font-mono text-sm text-slate-500">No active sessions - you may have just been signed out.</p>
          )}
          {sessionsQuery.data && sessionsQuery.data.length > 0 && (
            <ul className="flex flex-col gap-3">
              {sessionsQuery.data.map((s) => (
                <li
                  key={s.id}
                  className="flex flex-wrap items-center justify-between gap-3 rounded border border-slate-800 bg-void/40 px-4 py-3"
                >
                  <div className="font-mono text-xs text-slate-300">
                    <p>
                      Started <span className="text-slate-200">{formatDate(s.sessionStartedAt)}</span>
                    </p>
                    <p className="mt-1 text-slate-500">Expires {formatDate(s.expiresAt)}</p>
                  </div>
                  <button
                    onClick={() => setPendingRevoke(s)}
                    className="shrink-0 rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 transition hover:border-severity-critical/50 hover:text-severity-critical"
                  >
                    End session
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {pendingRevoke && (
        <Modal title="End session" onClose={() => setPendingRevoke(null)}>
          <p className="mb-4 text-sm text-slate-300">
            End the session started <span className="font-mono text-neon-cyan">{formatDate(pendingRevoke.sessionStartedAt)}</span>?
            If that's the device or browser you're using right now, you'll be signed out immediately.
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
              {revokeMutation.isPending ? "Ending…" : "End session"}
            </button>
          </div>
          {revokeMutation.isError && (
            <p role="alert" className="mt-2 font-mono text-xs text-severity-critical">
              {(revokeMutation.error as Error)?.message ?? "Failed to end session."}
            </p>
          )}
        </Modal>
      )}
    </Shell>
  );
}
