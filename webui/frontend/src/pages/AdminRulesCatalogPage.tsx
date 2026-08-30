import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import type { RulesCatalogEntry, Severity } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

async function fetchRulesCatalog(): Promise<RulesCatalogEntry[]> {
  const res = await apiFetch("/api/v1/rules-catalog");
  if (!res.ok) throw new Error("Failed to load the rules catalog.");
  return res.json();
}

async function setRuleEnabled(ruleId: string, enabled: boolean): Promise<RulesCatalogEntry> {
  const res = await apiFetch(`/api/v1/rules-catalog/${ruleId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  if (!res.ok) throw new Error("Failed to update the rule.");
  return res.json();
}

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "text-severity-critical",
  HIGH: "text-severity-high",
  MEDIUM: "text-severity-medium",
  LOW: "text-severity-low",
  INFO: "text-severity-info",
};

/** Same left-edge accent bar as FindingCard/Dashboard's "Top open findings" - a security team
 * browsing "what does this tool check for" benefits from the same at-a-glance severity scan as
 * the actual findings views, for consistency across the whole app. */
const SEVERITY_ACCENT: Record<Severity, string> = {
  CRITICAL: "border-l-severity-critical",
  HIGH: "border-l-severity-high",
  MEDIUM: "border-l-severity-medium",
  LOW: "border-l-severity-low",
  INFO: "border-l-severity-info",
};

/** Every check Bloodhound runs, grouped by category - in-product documentation of the whole rules catalog built up across Milestones 3-6b. */
export function AdminRulesCatalogPage() {
  usePageTitle("Rules Catalog");
  const rulesQuery = useQuery({ queryKey: ["rules-catalog"], queryFn: fetchRulesCatalog });
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const queryClient = useQueryClient();

  const toggleMutation = useMutation({
    mutationFn: ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) => setRuleEnabled(ruleId, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules-catalog"] }),
  });

  const categories = useMemo(() => {
    if (!rulesQuery.data) return [];
    return Array.from(new Set(rulesQuery.data.map((r) => r.category))).sort();
  }, [rulesQuery.data]);

  const filtered = useMemo(() => {
    if (!rulesQuery.data) return [];
    return categoryFilter === "ALL" ? rulesQuery.data : rulesQuery.data.filter((r) => r.category === categoryFilter);
  }, [rulesQuery.data, categoryFilter]);

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-2">
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
          <h1 className="font-display text-2xl font-bold text-neon-cyan">Rules catalog</h1>
        </div>
        <AdminSubNav />

        {rulesQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading rules…</p>}
        {rulesQuery.isError && <ErrorState message="Failed to load the rules catalog." onRetry={() => rulesQuery.refetch()} />}
        {toggleMutation.isError && (
          <p className="mb-4 font-mono text-xs text-severity-critical">
            {(toggleMutation.error as Error)?.message ?? "Failed to update the rule."}
          </p>
        )}

        {rulesQuery.data && (
          <>
            <div className="mb-4 flex flex-wrap gap-2">
              <FilterChip label="ALL" active={categoryFilter === "ALL"} onClick={() => setCategoryFilter("ALL")} />
              {categories.map((c) => (
                <FilterChip key={c} label={c} active={categoryFilter === c} onClick={() => setCategoryFilter(c)} />
              ))}
            </div>
            <p className="mb-4 font-mono text-xs text-slate-400">
              {filtered.length} rule{filtered.length === 1 ? "" : "s"}
            </p>
            <div className="flex flex-col gap-2">
              {filtered.map((rule) => (
                <div
                  key={rule.ruleId}
                  className={`rounded-lg border border-l-4 border-neon-cyan/10 bg-panel/60 p-4 ${SEVERITY_ACCENT[rule.defaultSeverity]} ${
                    rule.enabled ? "" : "opacity-50"
                  }`}
                >
                  <div className="mb-1 flex items-center justify-between gap-3">
                    <span className={`font-mono text-[10px] font-bold uppercase tracking-widest ${SEVERITY_STYLES[rule.defaultSeverity]}`}>
                      {rule.defaultSeverity} · {rule.category}
                    </span>
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500">{rule.ruleId}</span>
                      <label
                        className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-slate-400"
                        title={rule.enabled ? "Disable this rule — its findings stop being reported and any already open are resolved" : "Enable this rule"}
                      >
                        <input
                          type="checkbox"
                          className="checkbox-cyber"
                          checked={rule.enabled}
                          disabled={toggleMutation.isPending}
                          onChange={(e) => toggleMutation.mutate({ ruleId: rule.ruleId, enabled: e.target.checked })}
                        />
                        {rule.enabled ? "Enabled" : "Disabled"}
                      </label>
                    </div>
                  </div>
                  <p className="mb-1 font-mono text-sm font-bold text-slate-100">{rule.title}</p>
                  <p className="mb-2 font-mono text-xs text-slate-400">{rule.description}</p>
                  <p className="font-mono text-xs text-neon-cyan/80">↳ {rule.remediationAdvice}</p>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </Shell>
  );
}

function FilterChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      aria-pressed={active}
      onClick={onClick}
      className={`rounded border px-2.5 py-1 font-mono text-[11px] uppercase tracking-widest transition ${
        active
          ? "border-neon-cyan bg-neon-cyan/10 text-neon-cyan"
          : "border-slate-700 text-slate-400 hover:border-neon-cyan/50 hover:text-neon-cyan"
      }`}
    >
      {label}
    </button>
  );
}
