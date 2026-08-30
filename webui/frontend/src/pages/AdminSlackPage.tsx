import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import { usePageTitle } from "../lib/usePageTitle";

/**
 * The server never sends the real webhook URL back (see SlackWebhookValidator#mask's javadoc -
 * it's a bearer secret, not an identifier) - webhookUrlMasked is enough to confirm which
 * integration is configured, never enough to post as it.
 */
interface SlackIntegration {
  webhookUrlMasked: string;
  enabled: boolean;
  notificationTypes: string[];
  ownTargetsOnly: boolean;
}

interface SaveSlackIntegrationInput {
  /** Blank means "leave the currently-stored webhook unchanged" - see AdminSlackPage's save handler. */
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

async function saveIntegration(orgId: string, body: SaveSlackIntegrationInput): Promise<SlackIntegration> {
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

interface TestSendResult {
  success: boolean;
  detail: string | null;
}

/**
 * Fires one real message against the currently-*saved* webhook and reports back whether it
 * actually landed - a product/ops review found this integration was entirely fire-and-forget:
 * SlackNotifier's real delivery path is deliberately async (so a slow/unreachable Slack endpoint
 * never delays the scan/finding pipeline that triggered it) and any failure only ever reached a
 * server log line, never this page. An admin who fat-fingers a webhook URL - or whose webhook
 * gets revoked from the Slack side later - previously found out only by noticing alerts had
 * quietly stopped, if they noticed at all.
 */
async function sendTestMessage(orgId: string): Promise<TestSendResult> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/slack-integration/test`, { method: "POST" });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || "Failed to send test message.");
  }
  return res.json();
}

export function AdminSlackPage() {
  usePageTitle("Slack Notifications");
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const queryClient = useQueryClient();

  // The server never sends the real webhook URL (see the SlackIntegration interface's comment) -
  // webhookUrl here is only ever what the admin is actively typing to SET or REPLACE it, never a
  // round-tripped value from the server. isEditingWebhook tracks whether that input is shown at
  // all: once an integration exists, the masked value displays read-only until "Change" is
  // clicked, so a save that only touches e.g. notification types can't accidentally blank out a
  // secret the frontend was never given the real value of in the first place.
  const [webhookUrl, setWebhookUrl] = useState("");
  const [isEditingWebhook, setIsEditingWebhook] = useState(true);
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
      setWebhookUrl("");
      setIsEditingWebhook(false);
      setEnabled(query.data.enabled);
      setTypes(query.data.notificationTypes);
      setOwnTargetsOnly(query.data.ownTargetsOnly);
    } else if (query.data === null) {
      setIsEditingWebhook(true);
    }
  }, [query.data]);

  const saveMutation = useMutation({
    // Blank webhookUrl (not currently editing it) tells the server "leave the stored webhook
    // unchanged" - see SlackIntegrationController#save's javadoc for the other half of this.
    mutationFn: () =>
      saveIntegration(orgId, {
        webhookUrl: isEditingWebhook ? webhookUrl : "",
        enabled,
        notificationTypes: types,
        ownTargetsOnly,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-slack-integration", orgId] });
      // A previous test result is only meaningful against whatever webhook was saved at the
      // time - stale "test succeeded" from before this save would be misleading once the URL
      // itself may have just changed.
      testMutation.reset();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteIntegration(orgId),
    onSuccess: () => {
      setWebhookUrl("");
      setIsEditingWebhook(true);
      setTypes([]);
      setOwnTargetsOnly(false);
      queryClient.invalidateQueries({ queryKey: ["admin-slack-integration", orgId] });
    },
  });

  const testMutation = useMutation({ mutationFn: () => sendTestMessage(orgId) });

  const urlLooksValid = webhookUrl === "" || SLACK_URL_PATTERN.test(webhookUrl);
  // While editing, a valid non-blank URL is required (blank would be read as "leave unchanged"
  // server-side, which isn't what a form the admin is actively filling in should silently do).
  const canSubmit = isEditingWebhook ? urlLooksValid && webhookUrl !== "" : true;

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

          {!isEditingWebhook && query.data ? (
            <div className="mb-2 flex items-center gap-3 rounded border border-slate-700 bg-void px-3 py-2">
              <code className="flex-1 font-mono text-xs text-slate-400" title="The full URL is a bearer secret - the server never sends it back to the browser, not even right after you set it.">
                {query.data.webhookUrlMasked}
              </code>
              <button
                type="button"
                onClick={() => {
                  setIsEditingWebhook(true);
                  testMutation.reset();
                }}
                className="shrink-0 font-mono text-[11px] uppercase tracking-widest text-neon-cyan hover:underline"
              >
                Change
              </button>
            </div>
          ) : (
            <>
              <input
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/…"
                autoFocus={query.data != null}
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
              {query.data && (
                <button
                  type="button"
                  onClick={() => {
                    setIsEditingWebhook(false);
                    setWebhookUrl("");
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

          <h3 className="mb-2 mt-4 font-mono text-xs uppercase tracking-widest text-slate-300">Send to Slack for</h3>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {NOTIFICATION_TYPES.map((t) => (
              <label key={t.value} className="flex items-center gap-2 font-mono text-xs text-slate-300">
                <input className="checkbox-cyber" type="checkbox" checked={types.includes(t.value)} onChange={() => toggleType(t.value)} />
                {t.label}
              </label>
            ))}
          </div>

          <label className="mt-4 flex items-center gap-2 font-mono text-xs text-slate-300">
            <input
              className="checkbox-cyber"
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
              disabled={saveMutation.isPending || !canSubmit}
              className="rounded bg-neon-magenta/90 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
            >
              {saveMutation.isPending ? "Saving…" : "Save"}
            </button>
            {query.data && (
              <>
                {/* Only meaningful against a webhook that's actually saved - testing whatever's
                    mid-edit in the URL field above would report on a URL that was never stored,
                    which is confusing at best if the admin then navigates away without saving. */}
                <button
                  type="button"
                  onClick={() => testMutation.mutate()}
                  disabled={testMutation.isPending || isEditingWebhook}
                  title={isEditingWebhook ? "Save the webhook URL before sending a test message." : undefined}
                  className="rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10 disabled:opacity-40"
                >
                  {testMutation.isPending ? "Sending…" : "Send test message"}
                </button>
                <button
                  type="button"
                  onClick={() => deleteMutation.mutate()}
                  disabled={deleteMutation.isPending}
                  className="font-mono text-xs uppercase tracking-widest text-severity-critical hover:underline"
                >
                  Remove integration
                </button>
              </>
            )}
          </div>
          {/* aria-live: the outcome of a manual "does this work" check is exactly the kind of
              confirmation a screen reader user needs announced, not just painted for sighted
              users - same reasoning as CopyButton's own live region. */}
          <div aria-live="polite">
            {testMutation.isSuccess &&
              (testMutation.data.success ? (
                <p className="mt-2 font-mono text-xs text-neon-cyan">✓ Test message sent - check your Slack channel.</p>
              ) : (
                <p className="mt-2 font-mono text-xs text-severity-critical">
                  ✕ Delivery failed{testMutation.data.detail ? `: ${testMutation.data.detail}` : "."}
                </p>
              ))}
            {testMutation.isError && (
              <p className="mt-2 font-mono text-xs text-severity-critical">
                {(testMutation.error as Error)?.message ?? "Failed to send test message."}
              </p>
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
