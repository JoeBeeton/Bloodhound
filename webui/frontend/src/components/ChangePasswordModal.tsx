import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
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

/** Closes the loop for an admin-created user (or the bootstrap admin) to rotate off a temporary/placeholder password. */
export function ChangePasswordModal({ onClose }: { onClose: () => void }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const mutate = useMutation({
    mutationFn: () => changePassword(currentPassword, newPassword),
    onSuccess: () => setDone(true),
    onError: (err) => setError(err instanceof Error ? err.message : "Failed to change password."),
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
          <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Current password</label>
          <input
            required
            type="password"
            autoComplete="current-password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        <div>
          <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">New password</label>
          <input
            required
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        <div>
          <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Confirm new password</label>
          <input
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
    </Modal>
  );
}
