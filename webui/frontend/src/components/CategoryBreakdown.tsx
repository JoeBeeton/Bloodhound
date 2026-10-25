import { SCORE_CATEGORIES, type ScoreCategory } from "../lib/types";
import { CATEGORY_WEIGHTS, UNSCORED_CATEGORY_REASON } from "../lib/scoring";

const CATEGORY_LABELS: Record<ScoreCategory, string> = {
  EXPOSURE: "Exposure",
  TLS: "TLS",
  DNS: "DNS",
  NETWORK: "Network",
  HEADERS: "Headers",
  SUBDOMAIN_HYGIENE: "Subdomain hygiene",
  WEB_APP: "Web app",
};

/** Same A/B/C/D/F thresholds the backend grades on (>=90/80/70/60), applied continuously for the bar fill color. */
function barColor(score: number): string {
  if (score >= 90) return "bg-neon-cyan";
  if (score >= 80) return "bg-neon-cyan/70";
  if (score >= 70) return "bg-neon-amber";
  if (score >= 60) return "bg-severity-high";
  return "bg-severity-critical";
}

export function CategoryBreakdown({ categoryScores }: { categoryScores: Record<ScoreCategory, number> | undefined }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-neon-cyan/20 bg-panel/60 p-4">
      {SCORE_CATEGORIES.map((category) => {
        const score = categoryScores?.[category];
        return (
          <div key={category} className="flex items-center gap-3">
            <span
              className="w-40 shrink-0 font-mono text-xs uppercase tracking-widest text-slate-400"
              title={`${Math.round(CATEGORY_WEIGHTS[category] * 100)}% of the overall score`}
            >
              {CATEGORY_LABELS[category]}
              <span className="ml-1 text-slate-600">{Math.round(CATEGORY_WEIGHTS[category] * 100)}%</span>
            </span>
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-void">
              {score !== undefined && (
                <div className={`h-full rounded-full ${barColor(score)}`} style={{ width: `${score}%` }} />
              )}
            </div>
            <span className="w-10 shrink-0 text-right font-mono text-xs text-slate-300">
              {score !== undefined ? score.toFixed(0) : "—"}
            </span>
          </div>
        );
      })}
      <p
        className="mt-1 border-t border-neon-cyan/10 pt-3 font-mono text-[10px] leading-relaxed text-slate-500"
        title={Object.entries(UNSCORED_CATEGORY_REASON)
          .map(([cat, reason]) => `${cat}: ${reason}`)
          .join("\n")}
      >
        Findings tagged BRAND, WHOIS, BREACH, or COMPOUND are tracked but never factored in above - hover for why.
      </p>
    </div>
  );
}
