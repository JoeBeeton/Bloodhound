import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";

interface OrgSettings {
  mcpEnabled: boolean;
}

async function fetchSettings(orgId: string): Promise<OrgSettings> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/settings`);
  if (!res.ok) throw new Error("Failed to load MCP settings.");
  return res.json();
}

async function saveSettings(orgId: string, body: OrgSettings): Promise<OrgSettings> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error("Failed to save MCP settings.");
  return res.json();
}

/**
 * Org-wide MCP kill switch - separate from the per-user MCP checkbox on the Users page (see
 * AdminUsersPage.tsx): both must be on for any user's MCP token to actually work (see
 * mcp.McpEnabledGuardFilter, which checks both live on every /mcp/** request).
 */
export function AdminMcpPage() {
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const queryClient = useQueryClient();

  const [mcpEnabled, setMcpEnabled] = useState(true);

  const query = useQuery({
    queryKey: ["admin-mcp-settings", orgId],
    queryFn: () => fetchSettings(orgId),
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
            <p className="mt-2 font-mono text-xs text-severity-critical">
              {(saveMutation.error as Error)?.message ?? "Failed to save."}
            </p>
          )}
        </form>
      </div>
    </Shell>
  );
}
