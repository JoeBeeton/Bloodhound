import { FINDING_CATEGORIES, SEVERITIES, type FindingCategory, type Severity } from "../lib/types";

const SEVERITY_ACTIVE_STYLES: Record<Severity, string> = {
  CRITICAL: "border-severity-critical bg-severity-critical/15 text-severity-critical",
  HIGH: "border-severity-high bg-severity-high/15 text-severity-high",
  MEDIUM: "border-severity-medium bg-severity-medium/15 text-severity-medium",
  LOW: "border-severity-low bg-severity-low/15 text-severity-low",
  INFO: "border-severity-info bg-severity-info/15 text-severity-info",
};

const CATEGORY_LABELS: Record<FindingCategory, string> = {
  EXPOSURE: "Exposure",
  TLS: "TLS",
  DNS: "DNS",
  NETWORK: "Network",
  HEADERS: "Headers",
  SUBDOMAIN_HYGIENE: "Subdomain hygiene",
  WHOIS: "WHOIS",
  BREACH: "Breach",
  WEB_APP: "Web app",
  BRAND: "Brand",
  COMPOUND: "Compound risk",
};

const INACTIVE_TOGGLE = "border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-200";

export interface FindingsFilterState {
  severities: Severity[];
  categories: FindingCategory[];
  /** Omitted/undefined means OPEN, matching the server's own default - see FindingRepository#findByTargetDetailed. */
  status?: "OPEN" | "RESOLVED";
}

function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/**
 * Severity + category multi-select toggles for a findings list, shared by the
 * target detail and subdomain detail pages. Filtering happens server-side
 * (FindingRepository.findByTargetDetailed's severity/category IN-clause
 * support) - this component only owns the selection UI and reports the
 * resulting comma-joined query params the caller's fetch function expects.
 */
export function FindingsFilterBar({
  value,
  onChange,
  resultCount,
}: {
  value: FindingsFilterState;
  onChange: (next: FindingsFilterState) => void;
  resultCount: number | undefined;
}) {
  const hasFilters = value.severities.length > 0 || value.categories.length > 0;
  const status = value.status ?? "OPEN";

  return (
    <div className="mb-4 flex flex-col gap-2 rounded-lg border border-neon-cyan/10 bg-panel/40 p-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-slate-500">Status</span>
        {(["OPEN", "RESOLVED"] as const).map((s) => (
          <button
            key={s}
            aria-pressed={status === s}
            onClick={() => onChange({ ...value, status: s })}
            className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest transition ${
              status === s ? "border-neon-cyan bg-neon-cyan/15 text-neon-cyan" : INACTIVE_TOGGLE
            }`}
          >
            {s === "OPEN" ? "Open" : "Resolved"}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-slate-500">Severity</span>
        {SEVERITIES.map((severity) => {
          const active = value.severities.includes(severity);
          return (
            <button
              key={severity}
              aria-pressed={active}
              onClick={() => onChange({ ...value, severities: toggle(value.severities, severity) })}
              className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest transition ${
                active ? SEVERITY_ACTIVE_STYLES[severity] : INACTIVE_TOGGLE
              }`}
            >
              {severity}
            </button>
          );
        })}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-slate-500">Category</span>
        {FINDING_CATEGORIES.map((category) => {
          const active = value.categories.includes(category);
          return (
            <button
              key={category}
              aria-pressed={active}
              onClick={() => onChange({ ...value, categories: toggle(value.categories, category) })}
              className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest transition ${
                active ? "border-neon-cyan bg-neon-cyan/15 text-neon-cyan" : INACTIVE_TOGGLE
              }`}
            >
              {CATEGORY_LABELS[category]}
            </button>
          );
        })}
      </div>
      <div className="flex items-center justify-between gap-3 border-t border-neon-cyan/10 pt-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500">
          {resultCount === undefined ? "…" : `${resultCount} result${resultCount === 1 ? "" : "s"}`}
        </span>
        {hasFilters && (
          <button
            // Preserves status - it's the primary Open/Resolved view mode, not an incidental
            // narrowing filter, so "Clear filters" while browsing Resolved findings must not
            // silently snap the view back to Open too (a real bug this fixed: the original
            // version dropped status entirely here, defaulting it back to OPEN).
            onClick={() => onChange({ severities: [], categories: [], status: value.status })}
            className="font-mono text-[10px] uppercase tracking-widest text-neon-magenta transition hover:text-neon-magenta/70"
          >
            Clear filters ✕
          </button>
        )}
      </div>
    </div>
  );
}
