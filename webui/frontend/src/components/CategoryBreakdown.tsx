import { SCORE_CATEGORIES, type ScoreCategory } from "../lib/types";

const CATEGORY_LABELS: Record<ScoreCategory, string> = {
  EXPOSURE: "Exposure",
  TLS: "TLS",
  DNS: "DNS",
  NETWORK: "Network",
  HEADERS: "Headers",
  SUBDOMAIN_HYGIENE: "Subdomain hygiene",
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
            <span className="w-40 shrink-0 font-mono text-xs uppercase tracking-widest text-slate-400">
              {CATEGORY_LABELS[category]}
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
    </div>
  );
}
