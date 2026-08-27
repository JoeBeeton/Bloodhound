import { ScoreImpactBadge } from "./ScoreImpactBadge";
import type { Finding, Severity } from "../lib/types";

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "border-severity-critical/50 text-severity-critical",
  HIGH: "border-severity-high/50 text-severity-high",
  MEDIUM: "border-severity-medium/50 text-severity-medium",
  LOW: "border-severity-low/50 text-severity-low",
  INFO: "border-severity-info/50 text-severity-info",
};

// Tier 2 module_types don't all share the "_DEEP" suffix (ZAP_ACTIVE_SCAN doesn't),
// so this can't just be a string-suffix check - keep the actual list here rather
// than duplicating central-server's TIER2_MODULE_TYPES constant across the wire.
const TIER2_MODULE_TYPES = new Set(["PORT_SCAN_DEEP", "ZAP_ACTIVE_SCAN"]);
function isTier2Finding(moduleType: string): boolean {
  return TIER2_MODULE_TYPES.has(moduleType);
}

/** Compound-risk findings (CompoundRiskAnalysisService) are synthesized from two or more other findings, not from a scan module directly - flag them so they read as a synthesized insight, not a raw scan result. */
function isCompoundFinding(category: string): boolean {
  return category === "COMPOUND";
}

/** Clickable finding summary card - shared by the target detail, subdomain detail, and dashboard findings lists. */
export function FindingCard({ finding, onSelect }: { finding: Finding; onSelect: () => void }) {
  return (
    <button
      onClick={onSelect}
      className={`w-full rounded-lg border bg-panel/60 p-4 text-left transition hover:bg-panel ${SEVERITY_STYLES[finding.severity]}`}
    >
      <div className="mb-1 flex items-center justify-between gap-3">
        <span className={`font-mono text-xs font-bold uppercase tracking-widest ${SEVERITY_STYLES[finding.severity]}`}>
          {finding.severity}
        </span>
        <div className="flex items-center gap-2">
          {isTier2Finding(finding.moduleType) && (
            <span className="rounded border border-neon-amber/50 px-1 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-neon-amber">
              Tier 2
            </span>
          )}
          {isCompoundFinding(finding.category) && (
            <span className="rounded border border-neon-magenta/50 px-1 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-neon-magenta">
              Chain
            </span>
          )}
          <span className="font-mono text-xs uppercase tracking-widest text-slate-400">{finding.category}</span>
        </div>
      </div>
      <p className="font-mono text-sm font-semibold text-slate-100">{finding.title}</p>
      <p className="mt-1 text-sm text-slate-400">{finding.description}</p>
      <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-xs text-slate-400">
          <span className="text-slate-600">{finding.displayId}</span> · asset: {finding.affectedAsset}
        </p>
        <ScoreImpactBadge impact={finding.scoreImpact} />
      </div>
    </button>
  );
}
