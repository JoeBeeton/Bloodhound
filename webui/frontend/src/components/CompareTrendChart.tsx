import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceArea,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartContainer } from "./ChartContainer";
import { GRADE_BANDS } from "../lib/gradeBands";
import type { CompareSeries } from "../lib/types";

const SATURATION = 85;
const LIGHTNESS = 62;
/** How close two hues are allowed to land before one gets nudged - below this, two lines read as
 * "the same color" at a glance on this chart's line width/dot size. */
const PREFERRED_MIN_SEPARATION_DEG = 25;
/** Fallback resolution once more ids are packed into one comparison than PREFERRED_MIN_SEPARATION_DEG
 * can fit distinctly (360 / 25 = 14) - still comfortably above MAX_COMPARE_TARGETS (20, see
 * CompareController) since integer-degree hues give 360 possible values. */
const HUE_STEP_DEG = 1;

function hashToHue(id: string): number {
  let hash = 0;
  for (let i = 0; i < id.length; i++) {
    hash = (hash * 31 + id.charCodeAt(i)) | 0;
  }
  return ((hash % 360) + 360) % 360;
}

function hueDistance(a: number, b: number): number {
  const diff = Math.abs(a - b) % 360;
  return Math.min(diff, 360 - diff);
}

function normalizeHue(hue: number): number {
  return ((Math.round(hue) % 360) + 360) % 360;
}

/** Searches outward (both directions) from `preferred`, in HUE_STEP_DEG increments, for the
 * closest hue that's at least `minSeparation` from every already-assigned hue - staying as close
 * as possible to the id's own preferred hue rather than jumping to an arbitrary free slot, so a
 * nudge (when one is needed at all) is the smallest one that resolves the collision. */
function findHue(
  preferred: number,
  assigned: number[],
  minSeparation: number,
): number {
  if (assigned.every((h) => hueDistance(h, preferred) >= minSeparation)) {
    return preferred;
  }
  for (let offset = HUE_STEP_DEG; offset <= 180; offset += HUE_STEP_DEG) {
    for (const candidate of [preferred + offset, preferred - offset]) {
      const hue = normalizeHue(candidate);
      if (assigned.every((h) => hueDistance(h, hue) >= minSeparation)) {
        return hue;
      }
    }
  }
  // Only reachable when packing far more ids into one chart than this chart is ever asked to
  // (MAX_COMPARE_TARGETS is 20, comfortably under the 360 distinct integer-degree hues
  // available) - falls back to "merely distinct" rather than "well separated".
  for (let hue = 0; hue < 360; hue += HUE_STEP_DEG) {
    if (!assigned.includes(hue)) {
      return hue;
    }
  }
  return preferred;
}

/**
 * A product review found colors were assigned by each series' position in the `series` array
 * (`LINE_COLORS[i % LINE_COLORS.length]`) - deselecting one target shifted every other selected
 * target's index, so its line's color changed too, and re-adding a target later gave it whatever
 * color its new position happened to land on rather than the one it had before.
 *
 * <p>A follow-up report found colors were STILL visibly shuffling even after that fix: with only
 * 6 fixed hex colors and a hash-mod-6 assignment, two different targets landing on the same slot
 * was the common case, not a rare one (6 items into 6 slots is a >90% chance of at least one
 * collision) - so which two targets happened to share a color kept changing as the selection
 * changed, even though each individual target's own color was technically stable. Fixes both
 * complaints at once: every id still gets a color purely as a function of its own hash (hashed to
 * a position on the HSL hue wheel instead of an index into a 6-color array), so a target's
 * preferred color never depends on what else is selected - but this function also takes the
 * *whole* currently-selected set, sorted by id (not selection order, so the result never depends
 * on which order targets were added/removed in) and nudges any hue that collides with an
 * already-assigned one for THIS set just far enough around the wheel to stay visually distinct.
 * A target's color only ever moves off its preferred hue when another id currently on the same
 * chart would otherwise be indistinguishable from it - adding or removing an unrelated target
 * never touches it.
 */
export function colorsForSeries(ids: string[]): Map<string, string> {
  const sorted = [...new Set(ids)].sort();
  const assigned: number[] = [];
  const result = new Map<string, string>();
  for (const id of sorted) {
    const preferred = hashToHue(id);
    const minSeparation =
      assigned.length === 0
        ? 360
        : Math.min(PREFERRED_MIN_SEPARATION_DEG, 360 / (assigned.length + 1));
    const hue = findHue(preferred, assigned, minSeparation);
    assigned.push(hue);
    result.set(id, `hsl(${hue}, ${SATURATION}%, ${LIGHTNESS}%)`);
  }
  return result;
}

export type CompareScoreMode = "tier1" | "full";

interface SeriesPoint {
  computedAtMs: number;
  score: number;
}

/** Each target scans on its own schedule, so one series rarely has a real point at exactly the
 * moment another series does - shared by both the Line data and the tooltip below so they always
 * agree on what a series' own history actually contains. */
export function seriesPoints(
  s: CompareSeries,
  mode: CompareScoreMode,
): SeriesPoint[] {
  return s.history.map((h) => ({
    computedAtMs: new Date(h.computedAt).getTime(),
    score:
      mode === "tier1"
        ? (h.tier1OverallScore ?? h.overallScore)
        : h.overallScore,
  }));
}

export interface TooltipRow {
  targetId: string;
  name: string;
  score: number;
}

/**
 * Recharts bug found via a live report: when every Line in a chart supplies its own independent
 * `data` array (this chart's whole reason for being, since each target scans on its own schedule
 * - see the component's own doc comment below) rather than one shared dataset keyed by a common
 * field, Recharts' built-in Tooltip does not compute each line's own value at the hovered
 * position - it was observed showing every single series in the tooltip as the SAME number
 * (whichever series' point the cursor happened to be nearest to), even though the underlying
 * per-series data was correct the whole time (confirmed directly against the API response).
 *
 * <p>This ignores Recharts' own (buggy) `payload` array entirely and instead, for each series,
 * finds that series' own nearest real point to `label` (the hovered position's x value, which
 * Recharts computes correctly since it comes from the shared numeric XAxis scale, not from any
 * one series' data). A nearest-point lookup - not an interpolated value - matches what the Line
 * itself represents between two real scans: a security score is a step function, only ever
 * actually changing at a real scan's completion, so "value as of this moment" for a series with
 * no scan exactly here is honestly "whatever its last known value was," not a fabricated blend
 * between two unrelated targets' scan times.
 */
export function compareTooltipRows(
  series: CompareSeries[],
  mode: CompareScoreMode,
  label: number,
): TooltipRow[] {
  return series
    .map((s) => {
      const points = seriesPoints(s, mode);
      if (points.length === 0) {
        return null;
      }
      const nearest = points.reduce((closest, p) =>
        Math.abs(p.computedAtMs - label) <
        Math.abs(closest.computedAtMs - label)
          ? p
          : closest,
      );
      return {
        targetId: s.targetId,
        name: `${s.hostname} (${s.targetType})`,
        score: nearest.score,
      };
    })
    .filter((row): row is TooltipRow => row !== null);
}

function CompareTooltipContent({
  active,
  label,
  series,
  mode,
  colors,
}: {
  active?: boolean;
  label?: number;
  series: CompareSeries[];
  mode: CompareScoreMode;
  colors: Map<string, string>;
}) {
  if (!active || label === undefined) {
    return null;
  }
  const rows = compareTooltipRows(series, mode, label);
  if (rows.length === 0) {
    return null;
  }
  return (
    <div
      style={{
        background: "#12071f",
        border: "1px solid rgba(0,240,255,0.3)",
        borderRadius: 6,
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 12,
        padding: "8px 12px",
      }}
    >
      <div style={{ color: "#7a8aa0", marginBottom: 4 }}>
        {new Date(label).toLocaleString()}
      </div>
      {rows.map((row) => (
        <div key={row.targetId} style={{ color: colors.get(row.targetId) }}>
          {row.name} : {row.score.toFixed(2)}
        </div>
      ))}
    </div>
  );
}

/** Same reasoning as ScoreTrendChart's own summarizeTrend - a screen-reader user needs the "our
 * score vs. competitors" comparison this chart exists for spelled out as text, not left to guess
 * from an unlabeled multi-line SVG. One clause per target with any history; targets with none yet
 * are silently skipped here the same way their Line simply never renders a series. */
export function summarizeComparison(
  series: CompareSeries[],
  mode: CompareScoreMode,
): string {
  const clauses = series
    .filter((s) => s.history.length > 0)
    .map((s) => {
      const latest = s.history[s.history.length - 1];
      const score =
        mode === "tier1"
          ? (latest.tier1OverallScore ?? latest.overallScore)
          : latest.overallScore;
      return `${s.hostname} at ${score.toFixed(0)}`;
    });
  if (clauses.length === 0) {
    return "Score comparison: no scan history yet for the selected targets.";
  }
  return `Score comparison (${mode === "tier1" ? "fair comparison" : "full picture"}): ${clauses.join(", ")}.`;
}

/**
 * The headline "our score vs. competitors over time" chart. Each target
 * scans on its own schedule, so timestamps rarely align across series —
 * rather than force a shared categorical X axis (which would leave most
 * cells empty), each Line gets its own {computedAtMs, score} data array and
 * they all share one numeric time XAxis, which is Recharts' supported
 * pattern for independently-timed series on one chart.
 *
 * `mode` selects which of a snapshot's two scores gets plotted: "tier1" (the
 * default, fair-comparison score excluding Tier 2-exclusive findings that
 * only ever accumulate on authorized/owned targets) or "full" (everything,
 * including deep-scan findings). A competitor with no Tier 2 history plots
 * identically in both modes - that's correct, not a bug, since it never had
 * Tier 2-exclusive findings to differ by.
 */
export function CompareTrendChart({
  series,
  mode,
}: {
  series: CompareSeries[];
  mode: CompareScoreMode;
}) {
  if (series.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        Select at least one target to compare.
      </p>
    );
  }
  if (!series.some((s) => s.history.length > 0)) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No scan history yet for the selected targets — run a scan to start the
        trend.
      </p>
    );
  }

  const colors = colorsForSeries(series.map((s) => s.targetId));

  return (
    <ChartContainer ariaLabel={summarizeComparison(series, mode)}>
      {/* left:0 (not a negative margin) + a wider YAxis: a negative left margin combined
          with a narrow axis width clips the leading digit(s) of 2-3 digit tick labels
          ("100" rendered as "0", "75" as "5") - found via Milestone 9's real screenshot
          review. right:28 leaves room so the final X-axis date label isn't clipped either. */}
      <LineChart margin={{ top: 8, right: 28, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,240,255,0.1)" />
        {GRADE_BANDS.map((band) => (
          <ReferenceArea
            key={band.label}
            y1={band.y1}
            y2={band.y2}
            fill={band.color}
            fillOpacity={band.opacity}
            stroke="none"
            ifOverflow="extendDomain"
            // insideRight, not insideLeft: the numeric Y-axis ticks (0/25/50/75/100) already
            // live right at the left edge - a grade letter landing at the same height (e.g.
            // "C" beside "75") read as visual clutter, confirmed via a real screenshot review.
            // The right edge is otherwise empty space.
            label={{
              value: band.label,
              position: "insideRight",
              fill: band.color,
              fillOpacity: 0.5,
              fontSize: 10,
              fontFamily: "JetBrains Mono, monospace",
            }}
          />
        ))}
        <XAxis
          dataKey="computedAtMs"
          type="number"
          domain={["dataMin", "dataMax"]}
          tickFormatter={(ms: number) => new Date(ms).toLocaleDateString()}
          stroke="#7a8aa0"
          fontSize={11}
          fontFamily="JetBrains Mono, monospace"
        />
        <YAxis
          domain={[0, 100]}
          stroke="#7a8aa0"
          fontSize={11}
          fontFamily="JetBrains Mono, monospace"
          width={40}
        />
        <Tooltip
          content={
            <CompareTooltipContent
              series={series}
              mode={mode}
              colors={colors}
            />
          }
        />
        <Legend
          formatter={(value) => (
            <span
              style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}
            >
              {value}
            </span>
          )}
        />
        {series.map((s) => {
          const color = colors.get(s.targetId)!;
          // Pre-fix snapshots have no tier1OverallScore - fall back to the full score rather
          // than dropping the point, so old history doesn't just vanish from the "tier1" view.
          const data = seriesPoints(s, mode);
          return (
            <Line
              key={s.targetId}
              name={`${s.hostname} (${s.targetType})`}
              data={data}
              type="monotone"
              dataKey="score"
              stroke={color}
              strokeWidth={2}
              dot={{ r: 3, fill: color, strokeWidth: 0 }}
              activeDot={{ r: 6 }}
              isAnimationActive={false}
              connectNulls
            />
          );
        })}
      </LineChart>
    </ChartContainer>
  );
}
