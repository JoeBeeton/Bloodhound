import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { GradeBadge } from "../components/GradeBadge";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { colorForTargetType } from "../lib/attackSurfaceGraph";
import type { ScanRunDetail, Target, TargetType } from "../lib/types";
import { useAuth } from "../lib/useAuth";

async function fetchTargets(includeInactive: boolean): Promise<Target[]> {
  const res = await apiFetch(`/api/v1/targets?includeInactive=${includeInactive}`);
  if (!res.ok) throw new Error("Failed to load targets.");
  return res.json();
}

/** Soft remove/restore - PATCH isActive, reversible, keeps all history. */
async function setTargetActive(targetId: string, isActive: boolean): Promise<Target> {
  const res = await apiFetch(`/api/v1/targets/${targetId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ isActive }),
  });
  if (!res.ok) throw new Error(isActive ? "Failed to restore target." : "Failed to remove target.");
  return res.json();
}

/** Hard, cascading, irreversible delete - only reachable for an already-removed target, ADMIN only (see TargetController#delete's javadoc). */
async function deleteTargetPermanently(targetId: string): Promise<void> {
  const res = await apiFetch(`/api/v1/targets/${targetId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to permanently delete target.");
}

async function createTarget(input: { hostname: string; targetType: TargetType }): Promise<Target> {
  const res = await apiFetch("/api/v1/targets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const message = res.status === 409 ? "That domain is already tracked." : "Failed to add target.";
    throw new Error(message);
  }
  return res.json();
}

async function triggerScan(targetId: string): Promise<{ id: string }> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/scan`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to start scan.");
  return res.json();
}

async function triggerDeepScan(targetId: string): Promise<{ id: string }> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/scan/deep`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to start deep scan.");
  return res.json();
}

async function fetchRun(runId: string): Promise<ScanRunDetail> {
  const res = await apiFetch(`/api/v1/runs/${runId}`);
  if (!res.ok) throw new Error("Failed to load scan run.");
  return res.json();
}

const TARGET_TYPES: TargetType[] = ["OWN", "COMPETITOR", "WATCHLIST"];

export function TargetsPage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "ADMIN";
  const [showRemoved, setShowRemoved] = useState(false);
  const [search, setSearch] = useState("");
  const targetsQuery = useQuery({
    queryKey: ["targets", showRemoved],
    queryFn: () => fetchTargets(showRemoved),
  });
  const [activeRuns, setActiveRuns] = useState<Record<string, string>>({});
  const [pendingRemoval, setPendingRemoval] = useState<Target | null>(null);
  const [pendingDeletion, setPendingDeletion] = useState<Target | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");

  const [hostname, setHostname] = useState("");
  const [targetType, setTargetType] = useState<TargetType>("OWN");
  const [formError, setFormError] = useState<string | null>(null);

  const addTarget = useMutation({
    mutationFn: createTarget,
    onSuccess: () => {
      setHostname("");
      setFormError(null);
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
    onError: (err) => setFormError(err instanceof Error ? err.message : "Failed to add target."),
  });

  const setActive = useMutation({
    mutationFn: (input: { targetId: string; isActive: boolean }) => setTargetActive(input.targetId, input.isActive),
    onSuccess: () => {
      setPendingRemoval(null);
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });

  const deleteForever = useMutation({
    mutationFn: (targetId: string) => deleteTargetPermanently(targetId),
    onSuccess: () => {
      setPendingDeletion(null);
      setDeleteConfirmText("");
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    addTarget.mutate({ hostname, targetType });
  }

  function handleScanStarted(targetId: string, runId: string) {
    setActiveRuns((prev) => ({ ...prev, [targetId]: runId }));
  }

  return (
    <Shell>
      <div className="w-full max-w-3xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Attack Surface</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">Targets</h1>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowRemoved((v) => !v)}
              className={`font-mono text-xs uppercase tracking-widest transition ${
                showRemoved ? "text-neon-amber" : "text-slate-400 hover:text-neon-cyan"
              }`}
            >
              {showRemoved ? "Showing removed ✕" : "Show removed"}
            </button>
            <Link
              to="/dashboard"
              className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan"
            >
              ← Dashboard
            </Link>
          </div>
        </div>

        {targetsQuery.data && targetsQuery.data.length > 5 && (
          <div className="relative mb-4">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 font-mono text-xs text-slate-500">
              ⌕
            </span>
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by hostname…"
              className="w-full rounded border border-slate-700 bg-void py-2 pl-8 pr-3 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
            />
          </div>
        )}

        <form
          onSubmit={handleSubmit}
          className="mb-8 flex flex-col gap-3 rounded-lg border border-neon-cyan/20 bg-panel/80 p-4 sm:flex-row sm:items-end"
        >
          <div className="flex-1">
            <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Hostname</label>
            <input
              required
              placeholder="example.com"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
            />
          </div>
          <div>
            <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Type</label>
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value as TargetType)}
              className="select-cyber w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan sm:w-auto"
            >
              {TARGET_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <button
            type="submit"
            disabled={addTarget.isPending}
            className="rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
          >
            {addTarget.isPending ? "Adding…" : "Add target"}
          </button>
        </form>
        {formError && <p className="-mt-6 mb-6 font-mono text-xs text-severity-critical">{formError}</p>}

        {targetsQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading targets…</p>}
        {targetsQuery.isError && (
          <ErrorState message="Failed to load targets." onRetry={() => targetsQuery.refetch()} />
        )}

        <div className="flex flex-col gap-3">
          {(() => {
            const byRemoved = showRemoved
              ? (targetsQuery.data?.filter((t) => !t.isActive) ?? [])
              : (targetsQuery.data ?? []);
            const needle = search.trim().toLowerCase();
            const visible = needle ? byRemoved.filter((t) => t.hostname.toLowerCase().includes(needle)) : byRemoved;
            if (targetsQuery.data && visible.length === 0) {
              return (
                <p className="font-mono text-sm text-slate-400">
                  {needle
                    ? `No targets match "${search.trim()}".`
                    : showRemoved
                      ? "No removed targets."
                      : "No targets yet — add one above to start monitoring."}
                </p>
              );
            }
            return visible.map((target) => (
              <TargetRow
                key={target.id}
                target={target}
                activeRunId={activeRuns[target.id]}
                onScanStarted={(runId) => handleScanStarted(target.id, runId)}
                onRemove={() => setPendingRemoval(target)}
                onRestore={() => setActive.mutate({ targetId: target.id, isActive: true })}
                restorePending={setActive.isPending}
                onDeleteForever={isAdmin ? () => setPendingDeletion(target) : undefined}
              />
            ));
          })()}
        </div>
      </div>

      {pendingRemoval && (
        <Modal title="Remove target" onClose={() => setPendingRemoval(null)}>
          <p className="mb-4 text-sm text-slate-300">
            Remove <span className="font-mono text-neon-cyan">{pendingRemoval.hostname}</span> from monitoring? This
            pauses future scans but keeps all of its existing findings and scan history — you can restore it any
            time from the "Show removed" view.
          </p>
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setPendingRemoval(null)}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
            >
              Cancel
            </button>
            <button
              onClick={() => setActive.mutate({ targetId: pendingRemoval.id, isActive: false })}
              disabled={setActive.isPending}
              className="rounded border border-severity-critical/50 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10 disabled:opacity-40"
            >
              {setActive.isPending ? "Removing…" : "Remove"}
            </button>
          </div>
        </Modal>
      )}

      {pendingDeletion && (
        <Modal
          title="Delete target permanently"
          onClose={() => {
            setPendingDeletion(null);
            setDeleteConfirmText("");
          }}
        >
          <p className="mb-3 text-sm text-slate-300">
            This permanently deletes <span className="font-mono text-neon-cyan">{pendingDeletion.hostname}</span> and
            every finding, subdomain, scan run, and score history it has ever had.{" "}
            <span className="font-bold text-severity-critical">This cannot be undone.</span> Unlike "Remove," there
            is no restoring this target afterward.
          </p>
          <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
            Type <span className="text-neon-amber">{pendingDeletion.hostname}</span> to confirm
          </label>
          <input
            value={deleteConfirmText}
            onChange={(e) => setDeleteConfirmText(e.target.value)}
            className="mb-4 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-severity-critical"
            autoFocus
          />
          {deleteForever.isError && (
            <p className="mb-3 font-mono text-xs text-severity-critical">Failed to permanently delete target.</p>
          )}
          <div className="flex justify-end gap-3">
            <button
              onClick={() => {
                setPendingDeletion(null);
                setDeleteConfirmText("");
              }}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
            >
              Cancel
            </button>
            <button
              onClick={() => deleteForever.mutate(pendingDeletion.id)}
              disabled={deleteForever.isPending || deleteConfirmText !== pendingDeletion.hostname}
              className="rounded bg-severity-critical/90 px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-severity-critical disabled:cursor-not-allowed disabled:opacity-40"
            >
              {deleteForever.isPending ? "Deleting…" : "Delete permanently"}
            </button>
          </div>
        </Modal>
      )}
    </Shell>
  );
}

function TargetRow({
  target,
  activeRunId,
  onScanStarted,
  onRemove,
  onRestore,
  restorePending,
  onDeleteForever,
}: {
  target: Target;
  activeRunId?: string;
  onScanStarted: (runId: string) => void;
  onRemove: () => void;
  onRestore: () => void;
  restorePending: boolean;
  /** Only passed for ADMIN users - see TargetController#delete's ADMIN-only guard rail. */
  onDeleteForever?: () => void;
}) {
  const runQuery = useQuery({
    queryKey: ["run", activeRunId],
    queryFn: () => fetchRun(activeRunId!),
    enabled: !!activeRunId,
    refetchInterval: (query) => (query.state.data?.status === "RUNNING" ? 2000 : false),
  });

  const scanNow = useMutation({
    mutationFn: () => triggerScan(target.id),
    onSuccess: (run) => onScanStarted(run.id),
  });

  const deepScanNow = useMutation({
    mutationFn: () => triggerDeepScan(target.id),
    onSuccess: (run) => onScanStarted(run.id),
  });

  const status = runQuery.data?.status;

  return (
    <div
      className={`flex items-center justify-between rounded-lg border bg-panel/60 px-4 py-3 ${
        target.isActive ? "border-neon-cyan/10" : "border-slate-700/60 opacity-70"
      }`}
    >
      <div>
        <Link
          to={`/targets/${target.id}`}
          className="flex items-center gap-2 font-mono text-sm text-slate-200 hover:text-neon-cyan hover:underline"
        >
          <span
            className="inline-block h-2 w-2 shrink-0 rounded-full"
            style={{
              backgroundColor: colorForTargetType(target.targetType),
              boxShadow: `0 0 6px ${colorForTargetType(target.targetType)}`,
            }}
            aria-hidden="true"
          />
          {target.hostname}
        </Link>
        <p className="font-mono text-xs uppercase tracking-widest text-slate-400">
          {target.targetType} · {target.isActive ? "active" : "removed"}
        </p>
      </div>
      <div className="flex items-center gap-4">
        {!status && <GradeBadge grade={target.grade} score={target.overallScore} />}
        {status && <ScanStatusBadge status={status} />}
        {target.isActive ? (
          <>
            <button
              onClick={() => scanNow.mutate()}
              disabled={scanNow.isPending || status === "RUNNING"}
              className="rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10 disabled:opacity-40"
            >
              {status === "RUNNING" ? "Scanning…" : "Scan now"}
            </button>
            {/* Tier 2 only makes sense against domains you actually control - authorization is
                a separate, additional gate (see AuthorizationPanel on the target detail page),
                but offering the trigger at all for a competitor/watchlist target would be
                actively misleading, so it's hidden outright rather than just disabled. */}
            {target.targetType === "OWN" && (
              <span
                title={
                  target.authorizationStatus !== "AUTHORIZED"
                    ? "Authorize this target on its detail page before running a Tier 2 deep scan."
                    : `Deep-scan ${target.hostname}.`
                }
              >
                <button
                  onClick={() => deepScanNow.mutate()}
                  disabled={deepScanNow.isPending || status === "RUNNING" || target.authorizationStatus !== "AUTHORIZED"}
                  className="rounded border border-neon-amber/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-amber transition hover:bg-neon-amber/10 disabled:opacity-30"
                >
                  {status === "RUNNING" ? "Scanning…" : "Deep scan"}
                </button>
              </span>
            )}
            <button
              onClick={onRemove}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:border-severity-critical/50 hover:text-severity-critical"
            >
              Remove
            </button>
          </>
        ) : (
          <>
            <button
              onClick={onRestore}
              disabled={restorePending}
              className="rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10 disabled:opacity-40"
            >
              {restorePending ? "Restoring…" : "Restore"}
            </button>
            {onDeleteForever && (
              <button
                onClick={onDeleteForever}
                className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-500 transition hover:border-severity-critical/50 hover:text-severity-critical"
              >
                Delete permanently
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function ScanStatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    RUNNING: "text-neon-amber animate-pulse",
    COMPLETE: "text-neon-cyan",
    PARTIAL_FAILURE: "text-severity-critical",
  };
  return (
    <span className={`font-mono text-xs uppercase tracking-widest ${styles[status] ?? "text-slate-400"}`}>
      {status.replace("_", " ")}
    </span>
  );
}
