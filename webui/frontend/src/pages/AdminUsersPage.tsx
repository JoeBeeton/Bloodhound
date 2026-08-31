import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { CopyButton } from "../components/CopyButton";
import { ErrorState } from "../components/ErrorState";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import type { AdminUser, CreateUserResponse, UserRole, UserStatus } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

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
  patch: { role?: string; status?: string; mcpEnabled?: boolean },
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

/** A product/AppSec review found the role/status/MCP-access edits below never surfaced a
 * failure at all - a rejected PATCH (a network hiccup, a permission edge case) just left the
 * dropdown looking untouched with zero indication the click didn't actually take effect. Named
 * by field + email so a failure is specific enough to act on, not just "something went wrong". */
function describeUpdateTarget(
  variables: { userId: string; patch: { role?: string; status?: string; mcpEnabled?: boolean } },
  users: AdminUser[] | undefined,
): string {
  const email = users?.find((u) => u.id === variables.userId)?.email ?? "user";
  if (variables.patch.role !== undefined) return `role for ${email}`;
  if (variables.patch.status !== undefined) return `status for ${email}`;
  if (variables.patch.mcpEnabled !== undefined) return `MCP access for ${email}`;
  return email;
}

async function resetPassword(orgId: string, userId: string): Promise<CreateUserResponse> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/users/${userId}/reset-password`, { method: "POST" });
  if (!res.ok) {
    const message = res.status === 409 ? "This user signs in via SSO and has no local password to reset." : "Failed to reset password.";
    throw new Error(message);
  }
  return res.json();
}

export function AdminUsersPage() {
  usePageTitle("Users");
  const { user: currentUser } = useAuth();
  const orgId = currentUser?.organizationId ?? "";
  const queryClient = useQueryClient();
  const [showAddUser, setShowAddUser] = useState(false);
  // Shown-once temporary password from either flow (new user, or an admin resetting an existing
  // one) - both hand back the identical CreateUserResponse shape, so one reveal modal covers both.
  const [passwordReveal, setPasswordReveal] = useState<{ response: CreateUserResponse; mode: "created" | "reset" } | null>(
    null,
  );
  const [confirmingResetFor, setConfirmingResetFor] = useState<AdminUser | null>(null);

  const usersQuery = useQuery({ queryKey: ["admin-users", orgId], queryFn: () => fetchUsers(orgId), enabled: !!orgId });

  const mutate = useMutation({
    mutationFn: (input: { userId: string; patch: { role?: string; status?: string; mcpEnabled?: boolean } }) =>
      updateUser(orgId, input.userId, input.patch),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-users", orgId] }),
  });

  const resetMutate = useMutation({
    mutationFn: (userId: string) => resetPassword(orgId, userId),
    onSuccess: (response) => {
      setConfirmingResetFor(null);
      setPasswordReveal({ response, mode: "reset" });
      queryClient.invalidateQueries({ queryKey: ["admin-users", orgId] });
    },
  });

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-2 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">Users</h1>
          </div>
          <button
            onClick={() => setShowAddUser(true)}
            className="rounded bg-neon-magenta/90 px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta"
          >
            Add user
          </button>
        </div>
        <AdminSubNav />

        {mutate.isError && (
          <p role="status" className="mb-3 font-mono text-xs text-severity-critical">
            Failed to update {mutate.variables ? describeUpdateTarget(mutate.variables, usersQuery.data) : "user"}. Try
            again.
          </p>
        )}

        {usersQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading users…</p>}
        {usersQuery.isError && <ErrorState message="Failed to load users." onRetry={() => usersQuery.refetch()} />}

        {usersQuery.data && (
          // Six columns, four of them fixed-width, comfortably exceed any narrow viewport - this
          // is genuinely tabular data that can't reflow into a single column without losing its
          // structure, so the standard fix is letting THIS box scroll horizontally on its own
          // (confirmed live: previously the whole page did, pushing content off-screen with no
          // visible scrollbar to find it), not trying to force six columns into 375px.
          <div className="overflow-x-auto rounded-lg border border-neon-cyan/20 bg-panel/60">
            <div className="grid min-w-[860px] grid-cols-[1fr_1fr_140px_140px_70px_130px_120px] gap-2 border-b border-neon-cyan/20 px-4 py-2 font-mono text-[11px] uppercase tracking-widest text-slate-400">
              <span>Email</span>
              <span>Display name</span>
              <span>Role</span>
              <span>Status</span>
              <span>MCP</span>
              <span>Last login</span>
              <span>Password</span>
            </div>
            {usersQuery.data.map((u, i) => (
              <div
                key={u.id}
                className={`grid min-w-[860px] grid-cols-[1fr_1fr_140px_140px_70px_130px_120px] items-center gap-2 px-4 py-2.5 ${
                  i > 0 ? "border-t border-neon-cyan/10" : ""
                }`}
              >
                <span className="truncate font-mono text-sm text-slate-200">{u.email}</span>
                <span className="truncate font-mono text-sm text-slate-300">{u.displayName}</span>
                <select
                  value={u.role}
                  disabled={u.id === currentUser?.id || mutate.isPending}
                  onChange={(e) => mutate.mutate({ userId: u.id, patch: { role: e.target.value } })}
                  className="select-cyber rounded border border-slate-700 bg-void px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-neon-cyan disabled:opacity-40"
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
                  className={`select-cyber rounded border px-2 py-1 font-mono text-xs outline-none focus:border-neon-cyan disabled:opacity-40 ${
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
                <input
                  type="checkbox"
                  className="checkbox-cyber justify-self-start"
                  checked={u.mcpEnabled}
                  disabled={mutate.isPending}
                  onChange={(e) => mutate.mutate({ userId: u.id, patch: { mcpEnabled: e.target.checked } })}
                  title={`${u.mcpEnabled ? "Disable" : "Enable"} MCP access for this user`}
                />
                <LastLoginLabel lastLoginAt={u.lastLoginAt} />
                {u.identitySource === "LOCAL" ? (
                  <button
                    onClick={() => setConfirmingResetFor(u)}
                    className="justify-self-start rounded border border-slate-700 px-2 py-1 font-mono text-[11px] uppercase tracking-widest text-slate-300 transition hover:border-neon-amber/60 hover:text-neon-amber"
                    title="Generate a new temporary password and sign this user out everywhere"
                  >
                    Reset
                  </button>
                ) : (
                  <span
                    className="font-mono text-[11px] text-muted"
                    title={`This user is provisioned via ${u.identitySource} and has no local password to reset`}
                  >
                    {u.identitySource === "SAML" ? "SSO" : u.identitySource}
                  </span>
                )}
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
            setPasswordReveal({ response: created, mode: "created" });
            queryClient.invalidateQueries({ queryKey: ["admin-users", orgId] });
          }}
        />
      )}

      {confirmingResetFor && (
        <Modal title="Reset password?" onClose={() => setConfirmingResetFor(null)}>
          <p className="mb-3 text-sm text-slate-300">
            This generates a new temporary password for{" "}
            <span className="font-mono text-neon-cyan">{confirmingResetFor.email}</span> and immediately signs them
            out of every device — their current password stops working the moment you confirm.
          </p>
          {resetMutate.isError && (
            <p className="mb-3 font-mono text-xs text-severity-critical">
              {(resetMutate.error as Error)?.message ?? "Failed to reset password."}
            </p>
          )}
          <div className="flex gap-2">
            <button
              onClick={() => setConfirmingResetFor(null)}
              className="flex-1 rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 transition hover:border-slate-500"
            >
              Cancel
            </button>
            <button
              onClick={() => resetMutate.mutate(confirmingResetFor.id)}
              disabled={resetMutate.isPending}
              className="flex-1 rounded bg-neon-magenta/90 px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
            >
              {resetMutate.isPending ? "Resetting…" : "Reset password"}
            </button>
          </div>
        </Modal>
      )}

      {passwordReveal && (
        <Modal title={passwordReveal.mode === "created" ? "User created" : "Password reset"} onClose={() => setPasswordReveal(null)}>
          <p className="mb-3 text-sm text-slate-300">
            <span className="font-mono text-neon-cyan">{passwordReveal.response.user.email}</span>{" "}
            {passwordReveal.mode === "created"
              ? "can now log in with the temporary password below."
              : "has been signed out everywhere and can log back in with the temporary password below."}
          </p>
          <div className="mb-1 flex items-center gap-2 rounded border border-neon-amber/40 bg-void/60 px-3 py-2">
            <code className="flex-1 select-all break-all font-mono text-sm text-neon-amber">
              {passwordReveal.response.temporaryPassword}
            </code>
            <CopyButton value={passwordReveal.response.temporaryPassword} />
          </div>
          <p className="mb-4 font-mono text-xs text-severity-critical">
            This password is shown once and cannot be retrieved again. Relay it to{" "}
            {passwordReveal.response.user.displayName} securely — they should change it after logging in.
          </p>
          <button
            onClick={() => setPasswordReveal(null)}
            className="w-full rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10"
          >
            Done
          </button>
        </Modal>
      )}
    </Shell>
  );
}

const LAST_LOGIN_DATE_FORMAT: Intl.DateTimeFormatOptions = {
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
};

/**
 * last_login_at was written on every LOCAL/SAML sign-in from day one, but a product/AppSec
 * review found nothing anywhere ever read it back - an admin auditing who actually has access
 * had no way to spot a dormant account (SSO/SCIM-provisioned but never signed in, or an old
 * account nobody remembered to disable) versus one in active use.
 */
function LastLoginLabel({ lastLoginAt }: { lastLoginAt: string | null }) {
  if (!lastLoginAt) {
    return (
      <span className="font-mono text-xs text-muted" title="This account has never signed in">
        Never
      </span>
    );
  }
  return <span className="font-mono text-xs text-slate-400">{new Date(lastLoginAt).toLocaleString(undefined, LAST_LOGIN_DATE_FORMAT)}</span>;
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
          <label htmlFor="adduser-email" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
            Email
          </label>
          <input
            id="adduser-email"
            required
            type="email"
            // Matches CreateUserRequest's own @Size(max=320) (RFC 5321's max total email length) -
            // a security review found this form had no client-side cap at all, so a pasted huge
            // value hit the backend with no inline feedback, just a raw request failure.
            maxLength={320}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        <div>
          <label htmlFor="adduser-display-name" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
            Display name
          </label>
          <input
            id="adduser-display-name"
            required
            // Matches CreateUserRequest's own @Size(max=200), the same cap MCP client_name uses.
            maxLength={200}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
          />
        </div>
        <div>
          <label htmlFor="adduser-role" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
            Role
          </label>
          <select
            id="adduser-role"
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="select-cyber w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
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
