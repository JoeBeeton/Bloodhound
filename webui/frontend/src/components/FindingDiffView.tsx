import { useState } from "react";
// Same unbounded-list risk as TargetDetailPage's findings/subdomains lists
// (a subdomain-discovery-heavy diff can carry hundreds of "new" findings) -
// same fixed display cap, applied per-section below.
const DISPLAY_CAP = 25;
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import type { Finding, FindingDiffResponse } from "../lib/types";
import { ErrorState } from "./ErrorState";
import { FindingCard } from "./FindingCard";

async function fetchDiff(targetId: string, runId: string): Promise<FindingDiffResponse> {
  const res = await apiFetch(`/api/v1/targets/${targetId}/runs/${runId}/diff?against=previous`);
  if (!res.ok) throw new Error("Failed to load scan diff.");
  return res.json();
}

/**
 * Run-over-run findings diff for a target's most recent completed scan vs.
 * the one before it. `runId` is the target's latest score snapshot's
 * scanRunId - the parent page owns fetching that, this component just needs
 * somewhere to diff against.
 */
export function FindingDiffView({
  targetId,
  runId,
  onSelectFinding,
}: {
  targetId: string;
  runId: string | undefined;
  /** Same FindingCard used in "Open findings" above renders here too - a diff entry deserves
   * the same click-through-to-detail behavior as every other finding card on this page, not a
   * dead-end summary. */
  onSelectFinding: (finding: Finding) => void;
}) {
  const [showUnchanged, setShowUnchanged] = useState(false);
  const diffQuery = useQuery({
    queryKey: ["diff", targetId, runId],
    queryFn: () => fetchDiff(targetId, runId!),
    enabled: !!runId,
  });

  if (!runId) {
    return <p className="font-mono text-sm text-slate-400">Run a scan to enable the run-over-run diff.</p>;
  }
  if (diffQuery.isLoading) {
    return <p className="font-mono text-sm text-slate-400">Loading diff…</p>;
  }
  if (diffQuery.isError) {
    return <ErrorState message="Failed to load scan diff." onRetry={() => diffQuery.refetch()} />;
  }

  const diff = diffQuery.data;
  if (!diff) return null;

  if (!diff.baselineRunId) {
    return (
      <p className="font-mono text-sm text-slate-400">
        This is the first completed scan for this target — nothing to compare against yet. All {diff.newFindings.length}{" "}
        open finding{diff.newFindings.length === 1 ? "" : "s"} shown as new below.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <DiffSection
        title="New findings"
        findings={diff.newFindings}
        emptyLabel="No new findings since the previous scan."
        titleColor="text-severity-critical"
        onSelectFinding={onSelectFinding}
      />
      <DiffSection
        title="Resolved findings"
        findings={diff.resolvedFindings}
        emptyLabel="Nothing resolved since the previous scan."
        titleColor="text-neon-cyan"
        onSelectFinding={onSelectFinding}
      />
      <div>
        <button
          onClick={() => setShowUnchanged((v) => !v)}
          className="mb-2 font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-slate-300"
        >
          {showUnchanged ? "▾" : "▸"} Unchanged ({diff.unchangedFindings.length})
        </button>
        {showUnchanged && (
          <DiffSection
            title=""
            findings={diff.unchangedFindings}
            emptyLabel="—"
            titleColor="text-slate-400"
            muted
            onSelectFinding={onSelectFinding}
          />
        )}
      </div>
    </div>
  );
}

function DiffSection({
  title,
  findings,
  emptyLabel,
  titleColor,
  muted,
  onSelectFinding,
}: {
  title: string;
  findings: Finding[];
  emptyLabel: string;
  titleColor: string;
  muted?: boolean;
  onSelectFinding: (finding: Finding) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? findings : findings.slice(0, DISPLAY_CAP);
  return (
    <div>
      {title && (
        <h3 className={`mb-2 font-mono text-xs font-bold uppercase tracking-widest ${titleColor}`}>
          {title} ({findings.length})
        </h3>
      )}
      {findings.length === 0 ? (
        <p className="font-mono text-xs text-slate-400">{emptyLabel}</p>
      ) : (
        <div className="flex flex-col gap-2">
          {visible.map((f) => (
            <div key={f.id} className={muted ? "opacity-60" : ""}>
              <FindingCard finding={f} onSelect={() => onSelectFinding(f)} />
            </div>
          ))}
          {findings.length > DISPLAY_CAP && (
            <button
              onClick={() => setExpanded((v) => !v)}
              className="font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:text-neon-cyan/70"
            >
              {expanded ? "Show fewer ▴" : `Show all ${findings.length} ▾`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
