/** A small labeled number tile - dashboard's "totals at a glance" row. */
export function StatTile({ label, value, accent }: { label: string; value: number | string; accent?: string }) {
  return (
    <div className="flex flex-1 flex-col gap-1 rounded-lg border border-neon-cyan/20 bg-panel/60 px-4 py-3">
      <span className="font-mono text-xs uppercase tracking-widest text-slate-400">{label}</span>
      {/* font-mono, not font-display: Orbitron's stylized slashed-zero reads as a
          null/forbidden glyph at this size, which is actively confusing for a count
          that's legitimately supposed to be zero (e.g. "0 open critical findings") -
          found via Milestone 9's real screenshot review. Every other numeric/data
          display in the app already uses monospace for exactly this reason. */}
      <span className={`font-mono text-2xl font-bold ${accent ?? "text-slate-100"}`}>{value}</span>
    </div>
  );
}
