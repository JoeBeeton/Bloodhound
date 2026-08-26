import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import type { AdminUser, CreateUserResponse, UserRole, UserStatus } from "../lib/types";

const ROLES: UserRole[] = ["ADMIN", "ANALYST", "VIEWER"];
const STATUSES: UserStatus[] = ["ACTIVE", "DISABLED"];

async function fetchUsers(orgId: string): Promise<AdminUser[]> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/users`);
  if (!res.ok) throw new Error("Failed to load users.");
  return res.json();
}

async function updateUser(
  orgId: string,
  userId: string,
  patch: { role?: string; status?: string },
): Promise<AdminUser> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/users/${userId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!res.ok) throw new Error("Failed to update user.");
  return res.json();
}

async function createUser(
  orgId: string,
  input: { email: string; displayName: string; role: UserRole },
): Promise<CreateUserResponse> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/users`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const message = res.status === 409 ? "A user with that email already exists." : "Failed to create user.";
    throw new Error(message);
  }
  return res.json();
}

export function AdminUsersPage() {
  const { user: currentUser } = useAuth();
  const orgId = currentUser?.organizationId ?? "";
  const queryClient = useQueryClient();
  const [showAddUser, setShowAddUser] = useState(false);
  const [createdUser, setCreatedUser] = useState<CreateUserResponse | null>(null);

  const usersQuery = useQuery({ queryKey: ["admin-users", orgId], queryFn: () => fetchUsers(orgId), enabled: !!orgId });

  const mutate = useMutation({
    mutationFn: (input: { userId: string; patch: { role?: string; status?: string } }) =>
      updateUser(orgId, input.userId, input.patch),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-users", orgId] }),
  });

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">Users</h1>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowAddUser(true)}
              className="rounded bg-neon-magenta/90 px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta"
            >
              Add user
            </button>
            <Link to="/admin/rules-catalog" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
              Rules catalog →
            </Link>
            <Link to="/admin/sso" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
              SSO →
            </Link>
                        <Link to="/admin/slack" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
              Slack →
            </Link>
<Link to="/admin/scim" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
              SCIM →
            </Link>
            <Link to="/dashboard" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
              ← Dashboard
            </Link>
          </div>
        </div>

        {usersQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading users…</p>}
        {usersQuery.isError && <ErrorState message="Failed to load users." onRetry={() => usersQuery.refetch()} />}

        {usersQuery.data && (
          <div className="overflow-hidden rounded-lg border border-neon-cyan/20 bg-panel/60">
            <div className="grid grid-cols-[1fr_1fr_140px_140px] gap-2 border-b border-neon-cyan/20 px-4 py-2 font-mono text-[11px] uppercase tracking-widest text-slate-400">
              <span>Email</span>
              <span>Display name</span>
              <span>Role</span>
              <span>Status</span>
            </div>
            {usersQuery.data.map((u, i) => (
              <div
                key={u.id}
                className={`grid grid-cols-[1fr_1fr_140px_140px] items-center gap-2 px-4 py-2.5 ${
                  i > 0 ? "border-t border-neon-cyan/10" : ""
                }`}
              >
                <span className="truncate font-mono text-sm text-slate-200">{u.email}</span>
                <span className="truncate font-mono text-sm text-slate-300">{u.displayName}</span>
                <select
                  value={u.role}
                  disabled={u.id === currentUser?.id || mutate.isPending}
                  onChange={(e) => mutate.mutate({ userId: u.id, patch: { role: e.target.value } })}
                  className="rounded border border-slate-700 bg-void px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-neon-cyan disabled:opacity-40"
                  title={u.id === currentUser?.id ? "You can't change your own role" : undefined}
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                <select
                  value={u.status}
                  disabled={u.id === currentUser?.id || mutate.isPending}
                  onChange={(e) => mutate.mutate({ userId: u.id, patch: { status: e.target.value } })}
                  className={`rounded border px-2 py-1 font-mono text-xs outline-none focus:border-neon-cyan disabled:opacity-40 ${
                    u.status === "ACTIVE" ? "border-neon-cyan/40 text-neon-cyan" : "border-severity-critical/40 text-severity-critical"
                  }`}
                  title={u.id === currentUser?.id ? "You can't change your own status" : undefined}
                >
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
            ))}
          </div>
        )}
      </div>

      {showAddUser && (
        <AddUserModal
          orgId={orgId}
          onClose={() => setShowAddUser(false)}
          onCreated={(created) => {
            setShowAddUser(false);
            setCreatedUser(created);
            queryClient.invalidateQueries({ queryKey: ["admin-users", orgId] });
          }}
        />
      )}

      {createdUser && (
        <Modal title="User created" onClose={() => setCreatedUser(null)}>
          <p className="mb-3 text-sm text-slate-300">
            <span className="font-mono text-neon-cyan">{createdUser.user.email}</span> can now log in with the
            temporary password below.
          </p>
          <div className="mb-1 flex items-center gap-2 rounded border border-neon-amber/40 bg-void/60 px-3 py-2">
            <code className="flex-1 select-all break-all font-mono text-sm text-neon-amber">
              {createdUser.temporaryPassword}
            </code>
            <button
              onClick={() => navigator.clipboard?.writeText(createdUser.temporaryPassword)}
              className="shrink-0 font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan"
            >
              Copy
            </button>
          </div>
          <p className="mb-4 font-mono text-xs text-severity-critical">
            This password is shown once and cannot be retrieved again. Relay it to {createdUser.user.displayName}{" "}
            securely — they should change it after logging in.
          </p>
          <button
            onClick={() => setCreatedUser(null)}
            className="w-full rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10"
          >
            Done
          </button>
        </Modal>
      )}
    </Shell>
  );
}

function AddUserModal({
  orgId,
  onClose,
  onCreated,
}: {
  orgId: string;
  onClose: () => void;
  onCreated: (created: CreateUserResponse) => void;
}) {
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<UserRole>("VIEWER");
  const [error, setError] = useState<string | null>(null);

  const mutate = useMutation({
    mutationFn: () => createUser(orgId, { email, displayName, role }),
    onSuccess: onCreated,
    onError: (err) => setError(err instanceof Error ? err.message : "Failed to create user."),
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    mutate.mutate();
  }

  return (
    <Modal title="Add user" onClose={onClose}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <div>
          <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Email</label>
          <input
            required
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        <div>
          <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Display name</label>
          <input
            required
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        <div>
          <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Role</label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
        {error && <p className="font-mono text-xs text-severity-critical">{error}</p>}
        <button
          type="submit"
          disabled={mutate.isPending}
          className="mt-1 rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
        >
          {mutate.isPending ? "Creating…" : "Create user"}
        </button>
      </form>
    </Modal>
  );
}
