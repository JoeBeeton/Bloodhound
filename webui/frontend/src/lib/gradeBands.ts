/** Faint A-F grade bands for a 0-100 score chart - same 90/80/70/60 thresholds and color
 * language as GradeBadge/HealthGauge (cyan=healthy, amber=warning, magenta=critical), shared
 * between every recharts score-over-time chart (CompareTrendChart, ScoreTrendChart) so "where
 * does this line sit" reads as a grade at a glance instead of a mental Y-axis lookup. Opacity
 * kept low (0.02-0.05) so the bands read as a watermark, not something competing with the
 * actual score line(s) drawn on top. */
export const GRADE_BANDS: { y1: number; y2: number; color: string; opacity: number; label: string }[] = [
  { y1: 90, y2: 100, color: "#00f0ff", opacity: 0.05, label: "A" },
  { y1: 80, y2: 90, color: "#00f0ff", opacity: 0.025, label: "B" },
  { y1: 70, y2: 80, color: "#ffb800", opacity: 0.04, label: "C" },
  { y1: 60, y2: 70, color: "#ffb800", opacity: 0.02, label: "D" },
  { y1: 0, y2: 60, color: "#ff2e97", opacity: 0.04, label: "F" },
];
