import type { ReactElement } from "react";
import { ResponsiveContainer } from "recharts";

/**
 * Shared sizing/chrome for every Compare-page chart (trend, category
 * breakdown, findings severity) - one place to control "how big is the
 * graph" rather than three independently-sized containers drifting apart.
 * h-[32rem] (512px) replaces the original h-80 (320px) trend chart's own
 * fixed height - a product request to make the graph larger, applied once
 * here rather than per-chart.
 */
export function ChartContainer({
  ariaLabel,
  children,
}: {
  ariaLabel: string;
  children: ReactElement;
}) {
  return (
    <div
      className="h-[32rem] w-full rounded-lg border border-neon-cyan/20 bg-panel/60 p-4"
      role="img"
      aria-label={ariaLabel}
    >
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}
