import type { ScoreImpact } from "../lib/types";
import { unscoredCategoryExplanation } from "../lib/scoring";

/**
 * "+2.34 if fixed" for a finding that genuinely moves the score, or an honest
 * "Doesn't affect score" for one in an unscored category (WHOIS, BREACH, BRAND,
 * COMPOUND - see ScoreImpactCalculator's own short-circuit; WEB_APP carries real
 * 15% weight, it's not in this set) - deliberately not a bare "+0.00" for that
 * case, since that could be misread as "fixing this literally accomplishes
 * nothing" rather than "this category isn't part of the score." Renders nothing
 * at all when the endpoint didn't compute an impact (e.g. the historical
 * run-diff view).
 */
export function ScoreImpactBadge({ impact }: { impact: ScoreImpact | null | undefined }) {
  if (!impact) return null;

  if (!impact.affectsScore) {
    return (
      <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500" title={unscoredCategoryExplanation(impact.category)}>
        Doesn&rsquo;t affect score
      </span>
    );
  }

  const delta = impact.overallScoreDelta ?? 0;
  const label = delta > 0 ? `+${delta.toFixed(2)} if fixed` : delta < 0 ? `${delta.toFixed(2)} if fixed` : "No score change";
  const categoryRange = `${impact.category}: ${impact.categoryScoreBefore?.toFixed(2)} → ${impact.categoryScoreAfter?.toFixed(2)}`;
  const title =
    delta === 0
      ? `${categoryRange} (already at that level from other findings in this category - fixing this one specifically doesn't move it)`
      : categoryRange;

  return (
    <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-neon-cyan" title={title}>
      {label}
    </span>
  );
}
