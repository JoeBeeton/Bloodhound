import type { TlsGradeFactor } from "../lib/types";

/**
 * Same cyan/amber/magenta "healthy → critical" color language as GradeBadge, extended to the
 * finer A+/A-/B/C/D/F ladder TlsGradeCalculator produces (GradeBadge's own Grade type only has
 * five tiers and is paired with a 0-100 score, neither of which fits this grade - see its own
 * known-limitation note on why A+ is the practical ceiling today).
 */
const TLS_GRADE_STYLES: Record<string, string> = {
  "A+": "text-neon-cyan",
  A: "text-neon-cyan",
  "A-": "text-neon-cyan/80",
  B: "text-neon-amber",
  C: "text-neon-amber",
  D: "text-severity-high",
  F: "text-severity-critical",
};

function TlsGradeLetter({ grade }: { grade: string }) {
  const style = TLS_GRADE_STYLES[grade] ?? "text-slate-300";
  return <span className={`font-mono text-2xl font-bold ${style}`}>{grade}</span>;
}

/** One TLS configuration's full grade + the open findings that drove it - the presentational half, for the subdomain detail page. */
export function TlsGradePanel({ grade, factors }: { grade: string | null; factors: TlsGradeFactor[] }) {
  if (grade === null) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No TLS grade yet — run a scan to assess this host's certificate, protocol, and cipher configuration.
      </p>
    );
  }
  return (
    <div className="rounded-lg border border-neon-cyan/20 bg-panel/60 p-4">
      <div className="mb-3 flex items-center gap-3">
        <TlsGradeLetter grade={grade} />
        <span className="font-mono text-xs uppercase tracking-widest text-slate-400">
          {factors.length === 0
            ? "No TLS weaknesses found"
            : `${factors.length} factor${factors.length === 1 ? "" : "s"} affecting this grade`}
        </span>
      </div>
      {factors.length > 0 && (
        <div className="flex flex-col gap-2 border-t border-neon-cyan/10 pt-3">
          {factors.map((factor) => (
            <div key={factor.ruleId} className="font-mono text-xs">
              <span className="text-slate-300">{factor.title}</span>
              <span className="ml-2 text-neon-amber">— {factor.impact}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
