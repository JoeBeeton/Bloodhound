import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import { Modal } from "./Modal";

async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const res = await apiFetch("/api/v1/users/me/password", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ currentPassword, newPassword }),
  });
  if (!res.ok) {
    const message = res.status === 403 ? "Current password is incorrect." : "Failed to change password.";
    throw new Error(message);
  }
}

async function fetchActiveSessionCount(): Promise<number> {
  const res = await apiFetch("/api/v1/users/me/sessions/count");
  if (!res.ok) throw new Error("Failed to load session count.");
  const data: { count: number } = await res.json();
  return data.count;
}

/** Goes through webui's own /api/auth/** (not the plain /api/v1/** passthrough) - this is the
 * one action that needs the httpOnly refresh cookie webui/backend holds, to know which session
 * to leave alone. See AuthProxyController#logoutOtherSessions. */
async function logoutOtherSessions(): Promise<void> {
  const res = await apiFetch("/api/auth/logout-others", { method: "POST" });
  if (!res.ok) throw new Error("Failed to log out other sessions.");
}

/** Closes the loop for an admin-created user (or the bootstrap admin) to rotate off a temporary/placeholder password. */
export function ChangePasswordModal({ onClose }: { onClose: () => void }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [confirmingLogoutOthers, setConfirmingLogoutOthers] = useState(false);
  const [loggedOutOthers, setLoggedOutOthers] = useState(false);
  const queryClient = useQueryClient();

  const mutate = useMutation({
    mutationFn: () => changePassword(currentPassword, newPassword),
    onSuccess: () => setDone(true),
    onError: (err) => setError(err instanceof Error ? err.message : "Failed to change password."),
  });

  const sessionCountQuery = useQuery({ queryKey: ["active-session-count"], queryFn: fetchActiveSessionCount });
  const otherSessionCount = sessionCountQuery.data ? Math.max(0, sessionCountQuery.data - 1) : null;

  const logoutOthersMutate = useMutation({
    mutationFn: logoutOtherSessions,
    onSuccess: () => {
      setConfirmingLogoutOthers(false);
      setLoggedOutOthers(true);
      queryClient.invalidateQueries({ queryKey: ["active-session-count"] });
    },
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Passwords don't match.");
      return;
    }
    mutate.mutate();
  }

  if (done) {
    return (
      <Modal title="Password changed" onClose={onClose}>
        <p className="mb-4 text-sm text-slate-300">Your password has been updated.</p>
        <button
          onClick={onClose}
          className="w-full rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10"
        >
          Done
        </button>
      </Modal>
    );
  }

  return (
    <Modal title="Change password" onClose={onClose}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <div>
          <label htmlFor="changepw-current" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
            Current password
          </label>
          <input
            id="changepw-current"
            required
            type="password"
            autoComplete="current-password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        <div>
          <label htmlFor="changepw-new" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
            New password
          </label>
          <input
            id="changepw-new"
            required
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        <div>
          <label htmlFor="changepw-confirm" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
            Confirm new password
          </label>
          <input
            id="changepw-confirm"
            required
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        {error && <p className="font-mono text-xs text-severity-critical">{error}</p>}
        <button
          type="submit"
          disabled={mutate.isPending}
          className="mt-1 rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
        >
          {mutate.isPending ? "Changing…" : "Change password"}
        </button>
      </form>

      <div className="mt-5 border-t border-slate-800 pt-4">
        <h3 className="mb-1 font-mono text-xs uppercase tracking-widest text-slate-400">Active sessions</h3>
        {otherSessionCount === null ? (
          <p className="font-mono text-xs text-slate-500">Loading…</p>
        ) : loggedOutOthers ? (
          <p className="font-mono text-xs text-neon-cyan">You're now only signed in on this device.</p>
        ) : otherSessionCount === 0 ? (
          <p className="font-mono text-xs text-slate-500">You're only signed in on this device.</p>
        ) : confirmingLogoutOthers ? (
          <div>
            <p className="mb-2 font-mono text-xs text-slate-300">
              This signs out every other device currently using your account (
              {otherSessionCount} other session{otherSessionCount === 1 ? "" : "s"}) - this one stays signed in.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setConfirmingLogoutOthers(false)}
                className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
              >
                Cancel
              </button>
              <button
                onClick={() => logoutOthersMutate.mutate()}
                disabled={logoutOthersMutate.isPending}
                className="rounded border border-severity-critical/50 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10 disabled:opacity-40"
              >
                {logoutOthersMutate.isPending ? "Signing out…" : "Confirm sign-out"}
              </button>
            </div>
            {logoutOthersMutate.isError && (
              <p className="mt-2 font-mono text-xs text-severity-critical">Failed to log out other sessions.</p>
            )}
          </div>
        ) : (
          <div className="flex items-center justify-between gap-3">
            <p className="font-mono text-xs text-slate-300">
              Signed in on {otherSessionCount} other device{otherSessionCount === 1 ? "" : "s"} too.
            </p>
            <button
              onClick={() => setConfirmingLogoutOthers(true)}
              className="shrink-0 rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 transition hover:border-severity-critical/50 hover:text-severity-critical"
            >
              Log out other devices
            </button>
          </div>
        )}
      </div>
    </Modal>
  );
}
