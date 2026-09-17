import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { GradeBadge } from "../components/GradeBadge";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch, readErrorMessage } from "../lib/apiClient";
import type { PortfolioDetail, Target } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

async function fetchPortfolio(id: string): Promise<PortfolioDetail> {
  const res = await apiFetch(`/api/v1/portfolios/${id}`);
  if (!res.ok) throw new Error("Failed to load portfolio.");
  return res.json();
}

async function fetchTargets(): Promise<Target[]> {
  const res = await apiFetch("/api/v1/targets?includeInactive=false");
  if (!res.ok) throw new Error("Failed to load targets.");
  return res.json();
}

async function addMember(portfolioId: string, targetId: string): Promise<PortfolioDetail> {
  const res = await apiFetch(`/api/v1/portfolios/${portfolioId}/members`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targetId }),
  });
  if (!res.ok) throw new Error(await readErrorMessage(res, "Failed to add target to portfolio."));
  return res.json();
}

async function removeMember(portfolioId: string, targetId: string): Promise<PortfolioDetail> {
  const res = await apiFetch(`/api/v1/portfolios/${portfolioId}/members/${targetId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to remove target from portfolio.");
  return res.json();
}

async function deletePortfolio(portfolioId: string): Promise<void> {
  const res = await apiFetch(`/api/v1/portfolios/${portfolioId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete portfolio.");
}

export function PortfolioDetailPage() {
  const { id } = useParams<{ id: string }>();
  const portfolioId = id!;
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const portfolioQuery = useQuery({ queryKey: ["portfolio", portfolioId], queryFn: () => fetchPortfolio(portfolioId) });
  const targetsQuery = useQuery({ queryKey: ["targets", false], queryFn: fetchTargets });
  usePageTitle(portfolioQuery.data?.name);

  const [showAddMember, setShowAddMember] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["portfolio", portfolioId] });

  const addMemberMutation = useMutation({
    mutationFn: (targetId: string) => addMember(portfolioId, targetId),
    onSuccess: () => {
      setShowAddMember(false);
      setSelectedTargetId("");
      invalidate();
    },
  });

  const removeMemberMutation = useMutation({
    mutationFn: (targetId: string) => removeMember(portfolioId, targetId),
    onSuccess: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: () => deletePortfolio(portfolioId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["portfolios"] });
      navigate("/portfolios");
    },
  });

  if (portfolioQuery.isLoading) {
    return (
      <Shell>
        <p className="font-mono text-sm text-slate-400">Loading portfolio…</p>
      </Shell>
    );
  }
  if (portfolioQuery.isError || !portfolioQuery.data) {
    return (
      <Shell>
        <ErrorState message="Failed to load portfolio." onRetry={() => portfolioQuery.refetch()} />
      </Shell>
    );
  }

  const portfolio = portfolioQuery.data;
  const memberIds = new Set(portfolio.members.map((m) => m.targetId));
  const availableTargets = (targetsQuery.data ?? []).filter((t) => !memberIds.has(t.id));

  return (
    <Shell>
      <div className="w-full max-w-3xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <Link to="/portfolios" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
              ← Portfolios
            </Link>
            <h1 className="mt-1 font-display text-2xl font-bold text-neon-cyan">{portfolio.name}</h1>
            <div className="mt-1">
              <GradeBadge grade={portfolio.blendedGrade} score={portfolio.blendedScore} />
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowAddMember(true)}
              className="rounded border border-neon-cyan/40 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10"
            >
              Add target
            </button>
            <button
              onClick={() => setShowDeleteConfirm(true)}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:border-severity-critical/50 hover:text-severity-critical"
            >
              Delete portfolio
            </button>
          </div>
        </div>

        {portfolio.members.length === 0 && (
          <p className="font-mono text-sm text-slate-400">No targets in this portfolio yet — add one above.</p>
        )}

        <div className="flex flex-col gap-3">
          {portfolio.members.map((member) => (
            <div
              key={member.targetId}
              className="flex flex-wrap items-center justify-between gap-y-2 rounded-lg border border-neon-cyan/10 bg-panel/60 px-4 py-3"
            >
              <Link
                to={`/targets/${member.targetId}`}
                className="font-mono text-sm text-slate-200 hover:text-neon-cyan hover:underline"
              >
                {member.hostname}
              </Link>
              <div className="flex items-center gap-4">
                <GradeBadge grade={member.grade} score={member.overallScore} />
                <button
                  onClick={() => removeMemberMutation.mutate(member.targetId)}
                  disabled={removeMemberMutation.isPending}
                  className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:border-severity-critical/50 hover:text-severity-critical disabled:opacity-40"
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {showAddMember && (
        <Modal title="Add target" onClose={() => setShowAddMember(false)}>
          {availableTargets.length === 0 ? (
            <p className="font-mono text-sm text-slate-400">Every tracked target is already in this portfolio.</p>
          ) : (
            <>
              <label htmlFor="portfolio-add-target" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
                Target
              </label>
              <select
                id="portfolio-add-target"
                value={selectedTargetId}
                onChange={(e) => setSelectedTargetId(e.target.value)}
                className="select-cyber mb-4 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
              >
                <option value="" disabled>
                  Select a target…
                </option>
                {availableTargets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.hostname}
                  </option>
                ))}
              </select>
              {addMemberMutation.isError && (
                <p className="mb-3 font-mono text-xs text-severity-critical">
                  {(addMemberMutation.error as Error).message}
                </p>
              )}
              <div className="flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowAddMember(false)}
                  className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
                >
                  Cancel
                </button>
                <button
                  onClick={() => addMemberMutation.mutate(selectedTargetId)}
                  disabled={!selectedTargetId || addMemberMutation.isPending}
                  className="rounded bg-neon-magenta/90 px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
                >
                  {addMemberMutation.isPending ? "Adding…" : "Add"}
                </button>
              </div>
            </>
          )}
        </Modal>
      )}

      {showDeleteConfirm && (
        <Modal title="Delete portfolio" onClose={() => setShowDeleteConfirm(false)}>
          <p className="mb-4 text-sm text-slate-300">
            Delete <span className="font-mono text-neon-cyan">{portfolio.name}</span>? This only removes the
            grouping — every member target keeps its own scans, findings, and score history untouched.
          </p>
          {deleteMutation.isError && (
            <p className="mb-3 font-mono text-xs text-severity-critical">Failed to delete portfolio.</p>
          )}
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setShowDeleteConfirm(false)}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
            >
              Cancel
            </button>
            <button
              onClick={() => deleteMutation.mutate()}
              disabled={deleteMutation.isPending}
              className="rounded border border-severity-critical/50 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10 disabled:opacity-40"
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete"}
            </button>
          </div>
        </Modal>
      )}
    </Shell>
  );
}
