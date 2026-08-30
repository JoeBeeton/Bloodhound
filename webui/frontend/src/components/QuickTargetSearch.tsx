import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import { colorForTargetType } from "../lib/attackSurfaceGraph";
import type { Target } from "../lib/types";
import { GradeBadge } from "./GradeBadge";

async function fetchAllTargets(): Promise<Target[]> {
  const res = await apiFetch("/api/v1/targets?includeInactive=true");
  if (!res.ok) throw new Error("Failed to load targets.");
  return res.json();
}

const MAX_RESULTS = 8;

/**
 * A product/UX review found no way to reach a specific target except via the Targets page's own
 * in-page filter - on an org with dozens of targets, jumping from (say) a finding on Compare to a
 * different target's detail page meant navigating to Targets first, then scrolling/filtering
 * there, every time. This is a small always-available command-palette-style jump: Ctrl/Cmd+K (or
 * clicking the trigger) from any authenticated page, type a hostname substring, Enter/click lands
 * on that target's detail page directly.
 *
 * Deliberately client-side filtering over the org's full target list (includeInactive=true, so a
 * removed target is still reachable this way) rather than a new debounced backend search
 * endpoint - GET /api/v1/targets already returns every target in one unpaginated response (see
 * TargetsPage's own fetchTargets), and no org in this deployment has anywhere near enough targets
 * for that to be a real payload-size concern.
 */
export function QuickTargetSearch() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [highlighted, setHighlighted] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listboxId = "quick-target-search-listbox";

  const targetsQuery = useQuery({
    queryKey: ["targets-quick-search"],
    queryFn: fetchAllTargets,
    enabled: open,
    staleTime: 30_000,
  });

  const results = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const all = targetsQuery.data ?? [];
    const matches = needle ? all.filter((t) => t.hostname.toLowerCase().includes(needle)) : all;
    return matches.slice(0, MAX_RESULTS);
  }, [targetsQuery.data, query]);

  useEffect(() => {
    setHighlighted(0);
  }, [query, targetsQuery.data]);

  function close() {
    setOpen(false);
    setQuery("");
  }

  function goToTarget(target: Target) {
    close();
    navigate(`/targets/${target.id}`);
  }

  // Global Ctrl/Cmd+K, same idiom as GitHub/Linear/Notion's own quick-open - checked at the
  // document level (not scoped to this component's own DOM) since the whole point is opening it
  // from anywhere, including pages that have nothing to do with targets.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(true);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  // Same "invisible full-screen backdrop catches the outside click, Escape is the keyboard
  // equivalent" pattern as NotificationCenter's own panel.
  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        close();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setHighlighted((h) => Math.min(h + 1, results.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setHighlighted((h) => Math.max(h - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const target = results[highlighted];
        if (target) goToTarget(target);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, results, highlighted]);

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(true)}
        className="relative z-50 flex items-center gap-1.5 font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan"
        aria-label="Search targets"
      >
        <span aria-hidden>⌕</span>
        <span className="hidden sm:inline">Jump to…</span>
        <kbd className="hidden rounded border border-slate-700 px-1 py-0.5 font-mono text-[10px] text-slate-500 sm:inline">
          {navigator.platform?.toUpperCase().includes("MAC") ? "⌘K" : "Ctrl K"}
        </kbd>
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40 bg-void/60 backdrop-blur-sm" onClick={close} aria-hidden />
          <div className="fixed left-1/2 top-24 z-50 w-full max-w-lg -translate-x-1/2 px-4">
            <div
              role="combobox"
              aria-expanded={open}
              aria-haspopup="listbox"
              aria-owns={listboxId}
              aria-controls={listboxId}
              className="rounded-lg border border-neon-cyan/30 bg-panel shadow-glow-cyan"
            >
              <div className="flex items-center gap-2 border-b border-slate-700 px-4 py-3">
                <span aria-hidden className="text-slate-500">
                  ⌕
                </span>
                <input
                  ref={inputRef}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Jump to a target…"
                  aria-label="Search targets by hostname"
                  aria-autocomplete="list"
                  aria-controls={listboxId}
                  aria-activedescendant={results[highlighted] ? `quick-target-option-${results[highlighted].id}` : undefined}
                  className="w-full bg-transparent font-mono text-sm text-slate-200 outline-none placeholder:text-muted"
                />
                <button onClick={close} aria-label="Close search" className="font-mono text-xs text-slate-500 hover:text-slate-300">
                  ✕
                </button>
              </div>
              <div id={listboxId} role="listbox" aria-label="Matching targets" className="max-h-80 overflow-y-auto py-1">
                {targetsQuery.isLoading && <p className="px-4 py-3 font-mono text-xs text-slate-400">Loading targets…</p>}
                {targetsQuery.isError && (
                  <p className="px-4 py-3 font-mono text-xs text-severity-critical">Failed to load targets.</p>
                )}
                {targetsQuery.data && results.length === 0 && (
                  <p className="px-4 py-3 font-mono text-xs text-slate-400">
                    {query.trim() ? `No targets match "${query.trim()}".` : "No targets yet."}
                  </p>
                )}
                {results.map((target, i) => (
                  <button
                    key={target.id}
                    id={`quick-target-option-${target.id}`}
                    role="option"
                    aria-selected={i === highlighted}
                    onMouseEnter={() => setHighlighted(i)}
                    onClick={() => goToTarget(target)}
                    className={`flex w-full items-center justify-between gap-3 px-4 py-2 text-left transition ${
                      i === highlighted ? "bg-neon-cyan/10" : "hover:bg-void/60"
                    } ${!target.isActive ? "opacity-60" : ""}`}
                  >
                    <span className="flex items-center gap-2 truncate font-mono text-sm text-slate-200">
                      <span
                        className="inline-block h-2 w-2 shrink-0 rounded-full"
                        style={{
                          backgroundColor: colorForTargetType(target.targetType),
                          boxShadow: `0 0 6px ${colorForTargetType(target.targetType)}`,
                        }}
                        aria-hidden="true"
                      />
                      <span className="truncate">{target.hostname}</span>
                      {!target.isActive && <span className="shrink-0 text-[10px] uppercase text-slate-500">removed</span>}
                    </span>
                    <span className="shrink-0">
                      <GradeBadge grade={target.grade} score={target.overallScore} />
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
