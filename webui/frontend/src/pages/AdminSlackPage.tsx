import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";

interface SlackIntegration {
  webhookUrl: string;
  enabled: boolean;
  notificationTypes: string[];
  ownTargetsOnly: boolean;
}

const NOTIFICATION_TYPES: { value: string; label: string }[] = [
  { value: "SCAN_STARTED", label: "Scan started" },
  { value: "SCAN_COMPLETED", label: "Scan completed" },
  { value: "SCAN_FAILED", label: "Scan issues (partial failure)" },
  { value: "NEW_FINDINGS", label: "New findings (Medium+)" },
  { value: "NEW_SUBDOMAINS", label: "New subdomains" },
];

const SLACK_URL_PATTERN = /^https:\/\/hooks\.slack\.com\/services\/.+/;

async function fetchIntegration(orgId: string): Promise<SlackIntegration | null> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/slack-integration`);
  if (res.status === 204) return null;
  if (!res.ok) throw new Error("Failed to load Slack integration.");
  return res.json();
}

async function saveIntegration(orgId: string, body: SlackIntegration): Promise<SlackIntegration> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/slack-integration`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || "Failed to save Slack integration.");
  }
  return res.json();
}

async function deleteIntegration(orgId: string): Promise<void> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/slack-integration`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to remove Slack integration.");
}

export function AdminSlackPage() {
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const queryClient = useQueryClient();

  const [webhookUrl, setWebhookUrl] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [types, setTypes] = useState<string[]>(["NEW_FINDINGS", "SCAN_FAILED"]);
  const [ownTargetsOnly, setOwnTargetsOnly] = useState(false);

  const query = useQuery({
    queryKey: ["admin-slack-integration", orgId],
    queryFn: () => fetchIntegration(orgId),
    enabled: !!orgId,
  });

  useEffect(() => {
    if (query.data) {
      setWebhookUrl(query.data.webhookUrl);
      setEnabled(query.data.enabled);
      setTypes(query.data.notificationTypes);
      setOwnTargetsOnly(query.data.ownTargetsOnly);
    }
  }, [query.data]);

  const saveMutation = useMutation({
    mutationFn: () => saveIntegration(orgId, { webhookUrl, enabled, notificationTypes: types, ownTargetsOnly }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-slack-integration", orgId] }),
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteIntegration(orgId),
    onSuccess: () => {
      setWebhookUrl("");
      setTypes([]);
      setOwnTargetsOnly(false);
      queryClient.invalidateQueries({ queryKey: ["admin-slack-integration", orgId] });
    },
  });

  const urlLooksValid = webhookUrl === "" || SLACK_URL_PATTERN.test(webhookUrl);

  function toggleType(type: string) {
    setTypes((prev) => (prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]));
  }

  return (
    <Shell>
      <div className="mx-auto w-full max-w-4xl px-6 py-10">
        <div className="mb-2">
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
          <h1 className="font-display text-2xl font-bold text-neon-cyan">Slack Notifications</h1>
        </div>
        <AdminSubNav />

        {query.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
        {query.isError && <ErrorState message="Failed to load Slack integration." onRetry={() => query.refetch()} />}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            saveMutation.mutate();
          }}
          className="mb-6 rounded-lg border border-neon-cyan/20 bg-panel/60 p-5"
        >
          <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-neon-cyan">Webhook URL</h2>
          <p className="mb-3 font-mono text-xs text-slate-400">
            Create an Incoming Webhook in your Slack workspace and paste its URL here. Only genuine
            https://hooks.slack.com/services/... URLs are accepted.
          </p>
          <input
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/…"
            required
            className={`mb-1 w-full rounded border bg-void px-3 py-2 font-mono text-xs text-slate-200 outline-none ${
              urlLooksValid ? "border-slate-700 focus:border-neon-cyan" : "border-severity-critical"
            }`}
          />
          {!urlLooksValid && (
            <p className="mb-2 font-mono text-[11px] text-severity-critical">
              Must be a genuine https://hooks.slack.com/services/… URL.
            </p>
          )}

          <label className="mt-3 flex items-center gap-2 font-mono text-xs text-slate-300">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enabled
          </label>

          <h3 className="mb-2 mt-4 font-mono text-xs uppercase tracking-widest text-slate-300">Send to Slack for</h3>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {NOTIFICATION_TYPES.map((t) => (
              <label key={t.value} className="flex items-center gap-2 font-mono text-xs text-slate-300">
                <input type="checkbox" checked={types.includes(t.value)} onChange={() => toggleType(t.value)} />
                {t.label}
              </label>
            ))}
          </div>

          <label className="mt-4 flex items-center gap-2 font-mono text-xs text-slate-300">
            <input
              type="checkbox"
              checked={ownTargetsOnly}
              onChange={(e) => setOwnTargetsOnly(e.target.checked)}
            />
            Only notify for owned targets
          </label>
          <p className="mt-1 font-mono text-[11px] text-slate-500">
            When enabled, Slack only receives events about your own (OWN-type) domains —
            competitor/watchlist activity stays visible in-app but won't be sent here.
          </p>

          <div className="mt-5 flex items-center gap-3">
            <button
              type="submit"
              disabled={saveMutation.isPending || !urlLooksValid || webhookUrl === ""}
              className="rounded bg-neon-cyan/90 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-cyan disabled:opacity-50"
            >
              {saveMutation.isPending ? "Saving…" : "Save"}
            </button>
            {query.data && (
              <button
                type="button"
                onClick={() => deleteMutation.mutate()}
                disabled={deleteMutation.isPending}
                className="font-mono text-xs uppercase tracking-widest text-severity-critical hover:underline"
              >
                Remove integration
              </button>
            )}
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
