import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ErrorState } from "../components/ErrorState";
import { FindingActivityPulse } from "../components/FindingActivityPulse";
import { FindingDetailModal } from "../components/FindingDetailModal";
import { CATEGORY_LABELS, FindingsFilterBar, type FindingsFilterState } from "../components/FindingsFilterBar";
import { Shell } from "../components/Shell";
import { apiFetch, totalCountFromResponse } from "../lib/apiClient";
import { CATEGORY_ICONS } from "../lib/categoryIcons";
import { relativeTime } from "../lib/relativeTime";
import { SEVERITY_ACCENT, SEVERITY_STYLES } from "../lib/severityStyles";
import { fetchTargetsForFilter } from "../lib/targets";
import type { FindingActivityBucket, FindingCategory, OrgFinding, Severity } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";
import { orgFindingsFilterParams, parseStatusParam } from "./FindingsPage";

const PAGE_SIZE = 30;
const ACTIVITY_DAYS = 14;
const POLL_INTERVAL_MS = 20_000;

interface FeedPageData {
  items: OrgFinding[];
  totalCount: number;
}

async function fetchFeed(filters: FindingsFilterState, day: string | undefined, limit: number): Promise<FeedPageData> {
  const params = orgFindingsFilterParams(filters);
  if (day) params.set("day", day);
  params.set("limit", String(limit));
  params.set("offset", "0");
  const res = await apiFetch(`/api/v1/findings/feed?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load the findings feed.");
  const items: OrgFinding[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
}

async function fetchActivity(): Promise<FindingActivityBucket[]> {
  const res = await apiFetch(`/api/v1/findings/feed/activity?days=${ACTIVITY_DAYS}`);
  if (!res.ok) throw new Error("Failed to load findings activity.");
  return res.json();
}

/** "Today" / "Yesterday" / "This week" / "Earlier" - the feed's sticky group headers, computed
 * from the viewer's local calendar day (not a fixed 24h window) so "Yesterday" means what a
 * human means by it regardless of what time of day they're looking. */
function dayBucketLabel(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const startOfThat = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const diffDays = Math.round((startOfToday.getTime() - startOfThat.getTime()) / 86_400_000);
  if (diffDays <= 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7) return "This week";
  return "Earlier";
}

function groupByDayBucket(items: OrgFinding[]): [string, OrgFinding[]][] {
  const groups: [string, OrgFinding[]][] = [];
  for (const item of items) {
    // lastSeenAt, not createdAt - the feed is ordered by last-seen (see
    // FindingRepository#findRecentByOrganization's own doc comment), so grouping by a different
    // timestamp would produce out-of-order/non-contiguous day headers.
    const label = dayBucketLabel(item.lastSeenAt);
    const lastGroup = groups[groups.length - 1];
    if (lastGroup && lastGroup[0] === label) {
      lastGroup[1].push(item);
    } else {
      groups.push([label, [item]]);
    }
  }
  return groups;
}

/**
 * A dedicated, time-first view of everything happening across the org - the dashboard's "Recent
 * findings" widget is a fixed top-10 snapshot with no filters and no way to look further back;
 * this is the full-featured counterpart: an activity histogram to spot when things spiked, the
 * same severity/category/status/search/target filters the org-wide (severity-ranked) /findings
 * page already has, and live polling with a non-disruptive "N new" banner rather than yanking
 * the list out from under someone mid-read.
 */
export function FindingsFeedPage() {
  usePageTitle("Live Feed");
  const [searchParams, setSearchParams] = useSearchParams();
  const filters: FindingsFilterState = {
    severities: (searchParams.get("severity")?.split(",").filter(Boolean) ?? []) as Severity[],
    categories: (searchParams.get("category")?.split(",").filter(Boolean) ?? []) as FindingCategory[],
    status: parseStatusParam(searchParams.get("status")),
    search: searchParams.get("search") ?? undefined,
    targetId: searchParams.get("targetId") ?? undefined,
  };
  const setFilters = (next: FindingsFilterState) => {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        next.severities.length > 0 ? params.set("severity", next.severities.join(",")) : params.delete("severity");
        next.categories.length > 0 ? params.set("category", next.categories.join(",")) : params.delete("category");
        next.status && next.status !== "OPEN" ? params.set("status", next.status) : params.delete("status");
        next.search ? params.set("search", next.search) : params.delete("search");
        next.targetId ? params.set("targetId", next.targetId) : params.delete("targetId");
        return params;
      },
      { replace: true },
    );
  };

  const [selectedDay, setSelectedDay] = useState<string | undefined>(undefined);
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [live, setLive] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<OrgFinding | null>(null);

  // What's actually rendered - deliberately NOT the same thing as `query.data` once live polling
  // is involved. A background poll updates query.data immediately, but silently reflowing the
  // list out from under someone mid-read is exactly the "live feed" anti-pattern (see the module
  // doc comment) - this only gets replaced on an explicit user action (filter change, Load more,
  // or clicking the "N new" banner below), and the pending count in between is tracked separately.
  const [acknowledged, setAcknowledged] = useState<FeedPageData | null>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const [justArrivedIds, setJustArrivedIds] = useState<Set<string>>(new Set());
  const requestKeyRef = useRef<string>("");

  const query = useQuery({
    queryKey: ["findings-feed", filters, selectedDay, visibleCount],
    queryFn: () => fetchFeed(filters, selectedDay, visibleCount),
    refetchInterval: live ? POLL_INTERVAL_MS : false,
  });

  const activityQuery = useQuery({ queryKey: ["findings-feed-activity"], queryFn: fetchActivity });
  const targetsQuery = useQuery({ queryKey: ["targets-for-findings-filter"], queryFn: fetchTargetsForFilter });

  useEffect(() => {
    if (!query.data) return;
    const requestKey = JSON.stringify({ filters, selectedDay, visibleCount });
    if (requestKey !== requestKeyRef.current || acknowledged === null) {
      requestKeyRef.current = requestKey;
      setAcknowledged(query.data);
      setPendingCount(0);
      return;
    }
    const knownIds = new Set(acknowledged.items.map((f) => f.id));
    const newCount = query.data.items.filter((f) => !knownIds.has(f.id)).length;
    setPendingCount(newCount);
    // acknowledged is intentionally excluded - it's the thing this effect decides whether to
    // replace, not something a change to it should re-trigger the comparison against itself.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.data, filters, selectedDay, visibleCount]);

  function revealNewFindings() {
    if (!query.data) return;
    const knownIds = new Set((acknowledged?.items ?? []).map((f) => f.id));
    const newIds = new Set(query.data.items.filter((f) => !knownIds.has(f.id)).map((f) => f.id));
    setAcknowledged(query.data);
    setPendingCount(0);
    setJustArrivedIds(newIds);
    window.setTimeout(() => setJustArrivedIds(new Set()), 2500);
  }

  const items = acknowledged?.items ?? [];
  const totalCount = acknowledged?.totalCount;
  const groups = groupByDayBucket(items);
  const hasFilters = filters.severities.length > 0 || filters.categories.length > 0 || !!filters.search || !!filters.targetId;

  return (
    <Shell>
      <div className="w-full max-w-4xl text-left">
        <div className="mb-2 flex items-center justify-between gap-3">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Org-wide · chronological</p>
            <h1 className="flex items-center gap-2 font-display text-2xl font-bold text-neon-cyan">
              Live Feed
              {live && (
                <span
                  className="inline-block h-2 w-2 rounded-full bg-neon-cyan animate-feed-pulse"
                  aria-hidden="true"
                />
              )}
            </h1>
          </div>
          <button
            type="button"
            onClick={() => setLive((v) => !v)}
            aria-pressed={live}
            className={`rounded border px-2 py-1 font-mono text-[10px] font-bold uppercase tracking-widest transition ${
              live
                ? "border-neon-cyan bg-neon-cyan/15 text-neon-cyan"
                : "border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-200"
            }`}
          >
            {live ? "● Live" : "○ Paused"}
          </button>
        </div>

        {activityQuery.data && (
          <>
            <FindingActivityPulse
              buckets={activityQuery.data}
              selectedDay={selectedDay}
              onSelectDay={(day) => {
                setSelectedDay(day);
                setVisibleCount(PAGE_SIZE);
              }}
            />
            {/* The histogram counts every finding ever created that day, regardless of current
                status - a day can show a large bar here and a much smaller "N results" below once
                clicked, if most of what happened that day has since been resolved/reconciled. That's
                intentional (see FindingRepository#findDailyActivity's own javadoc), but silent
                otherwise reads as a bug, so it's called out explicitly right where the two numbers
                could disagree. */}
            <p className="-mt-3 mb-4 font-mono text-[10px] text-slate-500">
              Activity counts everything ever detected that day; the feed below only shows what's still {(filters.status ?? "OPEN").toLowerCase()}.
            </p>
          </>
        )}

        {selectedDay && (
          <div className="mb-3 flex items-center gap-2">
            <span className="rounded border border-neon-magenta/40 px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-neon-magenta">
              {new Date(selectedDay).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })}
            </span>
            <button
              type="button"
              onClick={() => setSelectedDay(undefined)}
              className="font-mono text-[10px] uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan"
            >
              Clear day ✕
            </button>
          </div>
        )}

        <FindingsFilterBar
          value={filters}
          onChange={(next) => {
            setFilters(next);
            setVisibleCount(PAGE_SIZE);
          }}
          resultCount={totalCount}
          targets={targetsQuery.data
            ?.slice()
            .sort((a, b) => a.hostname.localeCompare(b.hostname))
            .map((t) => ({ id: t.id, hostname: t.hostname }))}
        />

        {pendingCount > 0 && (
          <button
            onClick={revealNewFindings}
            className="mb-3 flex w-full items-center justify-center gap-2 rounded-lg border border-neon-cyan/40 bg-neon-cyan/10 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/20"
          >
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-neon-cyan animate-feed-pulse" aria-hidden="true" />
            {pendingCount} new finding{pendingCount === 1 ? "" : "s"} — click to view
          </button>
        )}

        {query.isLoading && <p className="font-mono text-sm text-slate-400">Loading feed…</p>}
        {query.isError && <ErrorState message="Failed to load the findings feed." onRetry={() => query.refetch()} />}
        {acknowledged && acknowledged.totalCount === 0 && (
          <p className="rounded-lg border border-neon-cyan/10 bg-panel/40 p-4 font-mono text-sm text-neon-cyan">
            {hasFilters || selectedDay
              ? `No ${(filters.status ?? "OPEN").toLowerCase()} findings match the selected filters.`
              : "Clean sweep — no open findings across your organization."}
          </p>
        )}

        {groups.map(([label, groupItems]) => (
          <div key={label} className="mb-4">
            <div className="sticky top-0 z-10 mb-2 -mx-1 bg-void/90 px-1 py-1 font-mono text-[10px] uppercase tracking-widest text-slate-500 backdrop-blur-sm">
              {label}
            </div>
            <div className="flex flex-col gap-2">
              {groupItems.map((f) => (
                <button
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className={`block w-full rounded-lg border border-l-4 bg-panel/60 p-3 text-left transition hover:bg-panel border-neon-cyan/10 ${SEVERITY_ACCENT[f.severity]} ${justArrivedIds.has(f.id) ? "animate-feed-arrive" : ""}`}
                >
                  <div className="mb-1 flex items-center justify-between gap-3">
                    <span className={`font-mono text-[10px] font-bold uppercase tracking-widest ${SEVERITY_STYLES[f.severity]}`}>
                      <span aria-hidden="true">{CATEGORY_ICONS[f.category as FindingCategory]}</span> {f.severity} ·{" "}
                      {CATEGORY_LABELS[f.category as FindingCategory] ?? f.category}
                    </span>
                    <span
                      className="whitespace-nowrap font-mono text-[10px] uppercase tracking-widest text-slate-500"
                      title={new Date(f.lastSeenAt).toLocaleString()}
                    >
                      {relativeTime(f.lastSeenAt)}
                    </span>
                  </div>
                  <p className="font-mono text-sm text-slate-200">{f.title}</p>
                  <div className="mt-1 flex items-center justify-between gap-2">
                    <span className="font-mono text-[10px] text-muted">{f.displayId}</span>
                    <span className="font-mono text-[10px] uppercase tracking-widest text-slate-400">{f.targetHostname}</span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        ))}

        {acknowledged && items.length < acknowledged.totalCount && (
          <button
            onClick={() => setVisibleCount((c) => c + PAGE_SIZE)}
            className="mt-1 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:text-neon-cyan/70"
          >
            Load more ▾ ({acknowledged.totalCount - items.length} more)
          </button>
        )}
      </div>
      {selectedFinding && <FindingDetailModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </Shell>
  );
}
