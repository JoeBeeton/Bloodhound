import type { Grade } from "../lib/types";

/** Same score->grade thresholds the backend's ScoringEngine uses (90/80/70/60) - see
 * GradeBadge's own comment. Individual targets always get their grade from the backend;
 * this is only needed here because the gauge shows an *aggregate* the backend never computes. */
function gradeForScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/** Parallel to GradeBadge's GRADE_STYLES, but as raw hex - an SVG stroke can't take a
 * Tailwind class, and drop-shadow glow needs the real color value anyway. */
const GRADE_COLOR: Record<Grade, string> = {
  A: "#00f0ff",
  B: "#00f0ff",
  C: "#ffb800",
  D: "#ffb800",
  F: "#ff2e97",
};

/**
 * A circular "at a glance" ring gauge for an aggregate score - the dashboard's hero
 * visual, complementing (not replacing) the per-target GradeBadge cards below it. Null
 * score (no own target has completed a scan yet) renders a dim, unfilled ring rather
 * than hiding the gauge entirely, so the header layout doesn't jump once scans land.
 */
export function HealthGauge({ score, label, size = 112 }: { score: number | null; label: string; size?: number }) {
  const strokeWidth = 9;
  const radius = size / 2 - strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const grade = score !== null ? gradeForScore(score) : null;
  const color = grade ? GRADE_COLOR[grade] : "#3a3a4a";
  const fraction = score !== null ? Math.max(0, Math.min(100, score)) / 100 : 0;

  return (
    <div className="flex flex-col items-center gap-1.5">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${label}: ${score !== null ? `${grade} · ${score.toFixed(0)}` : "not yet scanned"}`}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(148,163,184,0.15)" strokeWidth={strokeWidth} />
        {score !== null && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - fraction)}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
            style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dashoffset 0.8s ease" }}
          />
        )}
        <text
          x="50%"
          y="47%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="font-display font-bold"
          style={{ fontSize: size * 0.24, fill: color }}
        >
          {grade ?? "—"}
        </text>
        <text
          x="50%"
          y="68%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="font-mono"
          style={{ fontSize: size * 0.12, fill: "#7a8aa0" }}
        >
          {score !== null ? score.toFixed(0) : "n/a"}
        </text>
      </svg>
      <span className="font-mono text-[10px] uppercase tracking-widest text-slate-400">{label}</span>
    </div>
  );
}
