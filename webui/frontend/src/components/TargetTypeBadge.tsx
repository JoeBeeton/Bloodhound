import type { TargetType } from "../lib/types";

/** OWN vs COMPETITOR vs WATCHLIST - the distinction the whole /compare screen exists to make legible at a glance. */
const TYPE_STYLES: Record<TargetType, string> = {
  OWN: "border-neon-cyan/50 text-neon-cyan",
  COMPETITOR: "border-neon-magenta/50 text-neon-magenta",
  WATCHLIST: "border-neon-amber/50 text-neon-amber",
};

export function TargetTypeBadge({ targetType }: { targetType: TargetType }) {
  return (
    <span
      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest ${TYPE_STYLES[targetType]}`}
    >
      {targetType}
    </span>
  );
}
