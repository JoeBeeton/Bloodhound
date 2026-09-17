import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { GradeBadge } from "../components/GradeBadge";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch, readErrorMessage } from "../lib/apiClient";
import type { Portfolio } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

async function fetchPortfolios(): Promise<Portfolio[]> {
  const res = await apiFetch("/api/v1/portfolios");
  if (!res.ok) throw new Error("Failed to load portfolios.");
  return res.json();
}

async function createPortfolio(name: string): Promise<Portfolio> {
  const res = await apiFetch("/api/v1/portfolios", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!res.ok) {
    const message = res.status === 409 ? "A portfolio with that name already exists." : await readErrorMessage(res, "Failed to create portfolio.");
    throw new Error(message);
  }
  return res.json();
}

export function PortfoliosPage() {
  usePageTitle("Portfolios");
  const queryClient = useQueryClient();
  const portfoliosQuery = useQuery({ queryKey: ["portfolios"], queryFn: fetchPortfolios });
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: createPortfolio,
    onSuccess: () => {
      setName("");
      setFormError(null);
      setShowCreate(false);
      queryClient.invalidateQueries({ queryKey: ["portfolios"] });
    },
    onError: (err) => setFormError(err instanceof Error ? err.message : "Failed to create portfolio."),
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    create.mutate(name);
  }

  return (
    <Shell>
      <div className="w-full max-w-3xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Attack Surface</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">Portfolios</h1>
            <p className="mt-1 font-mono text-xs text-slate-400">
              Group related targets into one blended score, without merging their scans or findings.
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta"
          >
            New portfolio
          </button>
        </div>

        {portfoliosQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading portfolios…</p>}
        {portfoliosQuery.isError && (
          <ErrorState message="Failed to load portfolios." onRetry={() => portfoliosQuery.refetch()} />
        )}

        {portfoliosQuery.data && portfoliosQuery.data.length === 0 && (
          <p className="font-mono text-sm text-slate-400">
            No portfolios yet — create one to see a blended score across several targets.
          </p>
        )}

        <div className="flex flex-col gap-3">
          {portfoliosQuery.data?.map((p) => (
            <Link
              key={p.id}
              to={`/portfolios/${p.id}`}
              className="flex flex-wrap items-center justify-between gap-y-2 rounded-lg border border-neon-cyan/10 bg-panel/60 px-4 py-3 transition hover:border-neon-cyan/40"
            >
              <div>
                <p className="font-mono text-sm text-slate-200">{p.name}</p>
                <p className="font-mono text-xs uppercase tracking-widest text-slate-400">
                  {p.memberCount} target{p.memberCount === 1 ? "" : "s"}
                  {p.unscoredMemberCount > 0 &&
                    ` · ${p.unscoredMemberCount} not yet scored`}
                </p>
              </div>
              <GradeBadge grade={p.blendedGrade} score={p.blendedScore} />
            </Link>
          ))}
        </div>
      </div>

      {showCreate && (
        <Modal title="New portfolio" onClose={() => setShowCreate(false)}>
          <form onSubmit={handleSubmit}>
            <label htmlFor="portfolio-name" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
              Name
            </label>
            <input
              id="portfolio-name"
              required
              autoFocus
              placeholder="UK Credit Brands"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="mb-4 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
            />
            {formError && <p className="mb-3 font-mono text-xs text-severity-critical">{formError}</p>}
            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={create.isPending}
                className="rounded bg-neon-magenta/90 px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
              >
                {create.isPending ? "Creating…" : "Create"}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </Shell>
  );
}
