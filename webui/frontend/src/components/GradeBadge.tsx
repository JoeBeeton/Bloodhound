import type { Grade } from "../lib/types";

/**
 * Score/grade color coding, deliberately parallel to the severity palette
 * used for findings elsewhere: high score reads as "healthy" (cyan), low
 * score reads as "critical" (magenta) - same visual language, opposite
 * direction (a high finding-severity is bad, a high score is good).
 */
const GRADE_STYLES: Record<Grade, string> = {
  A: "text-neon-cyan",
  B: "text-neon-cyan/80",
  C: "text-neon-amber",
  D: "text-severity-high",
  F: "text-severity-critical",
};

export function GradeBadge({ grade, score }: { grade: Grade | null; score: number | null }) {
  if (grade === null || score === null) {
    return <span className="font-mono text-xs uppercase tracking-widest text-slate-400">not scanned</span>;
  }
  return (
    <span className={`font-mono text-xs font-bold uppercase tracking-widest ${GRADE_STYLES[grade]}`}>
      {grade} · {score.toFixed(0)}
    </span>
  );
}
