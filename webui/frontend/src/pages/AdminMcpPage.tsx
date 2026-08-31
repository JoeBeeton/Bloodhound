import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { ErrorState } from "../components/ErrorState";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch, readErrorMessage } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import { usePageTitle } from "../lib/usePageTitle";

interface OrgSettings {
  mcpEnabled: boolean;
  mcpSigningKeyGeneratedAt: string;
}

export interface McpConnection {
  registeredClientId: string;
  clientName: string;
  principalEmail: string;
  scopes: string[];
  lastActiveAt: string | null;
  refreshTokenExpiresAt: string | null;
}

async function fetchSettings(orgId: string): Promise<OrgSettings> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/settings`);
  if (!res.ok) throw new Error("Failed to load MCP settings.");
  return res.json();
}

async function saveSettings(orgId: string, body: { mcpEnabled: boolean }): Promise<OrgSettings> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error("Failed to save MCP settings.");
  return res.json();
}

async function fetchConnections(orgId: string): Promise<McpConnection[]> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/mcp/connections`);
  if (!res.ok) throw new Error("Failed to load connected clients.");
  return res.json();
}

/** Exported for isolated testing - mirrors TargetDetailPage's own triggerBulkDismiss pattern. */
export async function revokeConnection(orgId: string, conn: McpConnection): Promise<void> {
  const params = new URLSearchParams({ principalEmail: conn.principalEmail });
  const res = await apiFetch(
    `/api/v1/orgs/${orgId}/mcp/connections/${encodeURIComponent(conn.registeredClientId)}?${params}`,
    { method: "DELETE" },
  );
  if (!res.ok) throw new Error(await readErrorMessage(res, "Failed to revoke connection."));
}

/**
 * Org-wide MCP kill switch - separate from the per-user MCP checkbox on the Users page (see
 * AdminUsersPage.tsx): both must be on for any user's MCP token to actually work (see
 * mcp.McpEnabledGuardFilter, which checks both live on every /mcp/** request).
 */
export function AdminMcpPage() {
  usePageTitle("MCP Server");
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const queryClient = useQueryClient();

  const [mcpEnabled, setMcpEnabled] = useState(true);
  const [pendingRevoke, setPendingRevoke] = useState<McpConnection | null>(null);

  const query = useQuery({
    queryKey: ["admin-mcp-settings", orgId],
    queryFn: () => fetchSettings(orgId),
    enabled: !!orgId,
  });

  const connectionsQuery = useQuery({
    queryKey: ["admin-mcp-connections", orgId],
    queryFn: () => fetchConnections(orgId),
    enabled: !!orgId,
  });

  useEffect(() => {
    if (query.data) {
      setMcpEnabled(query.data.mcpEnabled);
    }
  }, [query.data]);

  const saveMutation = useMutation({
    mutationFn: () => saveSettings(orgId, { mcpEnabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-mcp-settings", orgId] }),
  });

  const revokeMutation = useMutation({
    mutationFn: (conn: McpConnection) => revokeConnection(orgId, conn),
    onSuccess: () => {
      setPendingRevoke(null);
      queryClient.invalidateQueries({ queryKey: ["admin-mcp-connections", orgId] });
    },
  });

  function formatDate(iso: string | null): string {
    return iso ? new Date(iso).toLocaleString() : "—";
  }

  return (
    <Shell>
      <div className="mx-auto w-full max-w-4xl px-6 py-10">
        <div className="mb-2">
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
          <h1 className="font-display text-2xl font-bold text-neon-cyan">MCP Server</h1>
        </div>
        <AdminSubNav />

        {query.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
        {query.isError && <ErrorState message="Failed to load MCP settings." onRetry={() => query.refetch()} />}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            saveMutation.mutate();
          }}
          className="mb-6 rounded-lg border border-neon-cyan/20 bg-panel/60 p-5"
        >
          <p className="mb-3 font-mono text-xs text-slate-400">
            Controls whether AI agents (Claude, or any OAuth2-authenticated MCP client) can connect to this
            organization's Bloodhound data via the Model Context Protocol server. Access is read-only —
            findings, targets, subdomains, and scan runs (including logs) can be viewed, nothing can be changed.
          </p>
          <p className="mb-3 font-mono text-xs text-slate-400">
            This is the org-wide switch. Each individual user also has their own MCP toggle on the{" "}
            <span className="text-neon-cyan">Users</span> page — both must be enabled for that user's MCP access
            to work.
          </p>
          {query.data && (
            <p className="mb-3 rounded border border-neon-amber/20 bg-neon-amber/5 px-3 py-2 font-mono text-xs text-slate-400">
              MCP signing key generated {new Date(query.data.mcpSigningKeyGeneratedAt).toLocaleString()} — every
              central-server restart generates a new one, which immediately invalidates every previously-issued MCP
              session. If a connected agent (e.g. Claude Desktop) suddenly needs to re-authenticate, this is why —
              it isn't specific to this org and nothing here needs fixing.
            </p>
          )}

          <label className="mt-3 flex items-center gap-2 font-mono text-xs text-slate-300">
            <input
              className="checkbox-cyber"
              type="checkbox"
              checked={mcpEnabled}
              onChange={(e) => setMcpEnabled(e.target.checked)}
            />
            MCP server enabled for this organization
          </label>

          <div className="mt-5 flex items-center gap-3">
            <button
              type="submit"
              disabled={saveMutation.isPending}
              className="rounded bg-neon-magenta/90 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
            >
              {saveMutation.isPending ? "Saving…" : "Save"}
            </button>
          </div>
          {saveMutation.isError && (
            <p role="alert" className="mt-2 font-mono text-xs text-severity-critical">
              {(saveMutation.error as Error)?.message ?? "Failed to save."}
            </p>
          )}
        </form>

        <div className="rounded-lg border border-slate-700 bg-panel/60 p-5">
          <h2 className="mb-1 font-display text-sm font-bold text-neon-cyan">Connected clients</h2>
          <p className="mb-4 font-mono text-xs text-slate-400">
            Every AI-agent client currently authorized against this org, one row per client-and-user pair. The
            toggle above cuts off every client at once — revoke a single connection here instead when only one
            needs to go.
          </p>

          {connectionsQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
          {connectionsQuery.isError && (
            <ErrorState message="Failed to load connected clients." onRetry={() => connectionsQuery.refetch()} />
          )}
          {connectionsQuery.data && connectionsQuery.data.length === 0 && (
            <p className="font-mono text-sm text-slate-500">No AI agents have connected yet.</p>
          )}
          {connectionsQuery.data && connectionsQuery.data.length > 0 && (
            <ul className="flex flex-col gap-3">
              {connectionsQuery.data.map((conn) => (
                <li
                  key={`${conn.registeredClientId}:${conn.principalEmail}`}
                  className="flex flex-wrap items-center justify-between gap-3 rounded border border-slate-800 bg-void/40 px-4 py-3"
                >
                  <div className="font-mono text-xs text-slate-300">
                    <p>
                      <span className="text-slate-100">{conn.clientName}</span>{" "}
                      <span className="text-slate-500">authorized by</span>{" "}
                      <span className="text-slate-200">{conn.principalEmail}</span>
                    </p>
                    <p className="mt-1 text-slate-500">
                      Last active {formatDate(conn.lastActiveAt)} · expires {formatDate(conn.refreshTokenExpiresAt)}
                      {conn.scopes.length > 0 && <> · scope: {conn.scopes.join(", ")}</>}
                    </p>
                  </div>
                  <button
                    onClick={() => setPendingRevoke(conn)}
                    className="shrink-0 rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 transition hover:border-severity-critical/50 hover:text-severity-critical"
                  >
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {pendingRevoke && (
        <Modal title="Revoke connection" onClose={() => setPendingRevoke(null)}>
          <p className="mb-4 text-sm text-slate-300">
            Revoke <span className="font-mono text-neon-cyan">{pendingRevoke.clientName}</span>'s access, authorized
            by <span className="font-mono text-neon-cyan">{pendingRevoke.principalEmail}</span>? That client will
            need to reconnect and get re-authorized before it can reach this org's data again.
          </p>
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setPendingRevoke(null)}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
            >
              Cancel
            </button>
            <button
              onClick={() => revokeMutation.mutate(pendingRevoke)}
              disabled={revokeMutation.isPending}
              className="rounded border border-severity-critical/50 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10 disabled:opacity-40"
            >
              {revokeMutation.isPending ? "Revoking…" : "Revoke"}
            </button>
          </div>
          {revokeMutation.isError && (
            <p role="alert" className="mt-2 font-mono text-xs text-severity-critical">
              {(revokeMutation.error as Error)?.message ?? "Failed to revoke connection."}
            </p>
          )}
        </Modal>
      )}
    </Shell>
  );
}
