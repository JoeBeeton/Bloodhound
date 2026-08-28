import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";

interface NotificationItem {
  id: string;
  type: string;
  severity: string;
  title: string;
  message: string;
  targetId: string | null;
  targetHostname: string | null;
  scanRunId: string | null;
  isRead: boolean;
  createdAt: string;
}

interface NotificationsResponse {
  notifications: NotificationItem[];
  unreadCount: number;
}

async function fetchNotifications(): Promise<NotificationsResponse> {
  const res = await apiFetch("/api/v1/notifications?limit=30");
  if (!res.ok) throw new Error("Failed to load notifications.");
  return res.json();
}

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: "text-severity-critical",
  HIGH: "text-severity-high",
  MEDIUM: "text-severity-medium",
  LOW: "text-severity-low",
  INFO: "text-severity-info",
};

// Near-real-time via polling, not a websocket - this whole app is TanStack-Query-polling-based
// already (scan status, dashboard, etc.), no push infrastructure exists, and adding one just for
// this feature would be a much bigger lift than the "popup when something new happens" bar
// actually needs.
const POLL_INTERVAL_MS = 25_000;
const TOAST_LIFETIME_MS = 6_000;

export function NotificationCenter() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [panelOpen, setPanelOpen] = useState(false);
  const [toasts, setToasts] = useState<NotificationItem[]>([]);
  const lastSeenCreatedAt = useRef<string | null>(null);
  const initialized = useRef(false);

  const query = useQuery({
    queryKey: ["notifications"],
    queryFn: fetchNotifications,
    refetchInterval: POLL_INTERVAL_MS,
  });

  useEffect(() => {
    if (!query.data) return;
    const items = query.data.notifications;
    if (!initialized.current) {
      // First load: just record the watermark, don't toast the user's entire existing
      // backlog on page open.
      initialized.current = true;
      lastSeenCreatedAt.current = items[0]?.createdAt ?? null;
      return;
    }
    const watermark = lastSeenCreatedAt.current;
    const fresh = watermark ? items.filter((n) => n.createdAt > watermark) : [];
    if (fresh.length > 0) {
      setToasts((prev) => [...fresh, ...prev]);
      lastSeenCreatedAt.current = items[0]?.createdAt ?? watermark;
      fresh.forEach((n) => {
        setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== n.id)), TOAST_LIFETIME_MS);
      });
    }
  }, [query.data]);

  async function markRead(id: string) {
    await apiFetch(`/api/v1/notifications/${id}/read`, { method: "PATCH" });
    queryClient.invalidateQueries({ queryKey: ["notifications"] });
  }

  async function markAllRead() {
    await apiFetch("/api/v1/notifications/mark-all-read", { method: "POST" });
    queryClient.invalidateQueries({ queryKey: ["notifications"] });
  }

  function goTo(n: NotificationItem) {
    setPanelOpen(false);
    if (!n.isRead) markRead(n.id);
    // Every current notification type is scan-related and carries a scanRunId - land the
    // user on that specific scan, not just the target's general page, so "12 new findings"
    // takes you straight to the run that found them rather than making you hunt for it.
    if (n.scanRunId) {
      navigate(`/scans/${n.scanRunId}`);
    } else if (n.targetId) {
      navigate(`/targets/${n.targetId}`);
    }
  }

  // Same "invisible full-screen backdrop catches the outside click" technique Modal.tsx uses,
  // just without a dimmed overlay (this is a small dropdown, not a modal) - a bell/panel
  // stacked at the highest z-index still receives its own clicks first, so this only ever
  // catches clicks genuinely outside the panel. Escape is the keyboard-only equivalent.
  useEffect(() => {
    if (!panelOpen) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setPanelOpen(false);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [panelOpen]);

  const unreadCount = query.data?.unreadCount ?? 0;

  return (
    <div className="relative">
      <button
        onClick={() => setPanelOpen((v) => !v)}
        className="relative font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan"
        aria-label="Notifications"
      >
        <span aria-hidden>🔔</span>
        {unreadCount > 0 && (
          <span className="absolute -right-2 -top-2 flex h-4 min-w-4 items-center justify-center rounded-full bg-neon-magenta px-1 font-mono text-[10px] font-bold text-void">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {panelOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setPanelOpen(false)} aria-hidden />
          <div className="absolute right-0 top-8 z-50 w-96 max-w-[90vw] rounded-lg border border-neon-cyan/20 bg-panel shadow-glow-cyan">
            <div className="flex items-center justify-between border-b border-slate-700 px-4 py-3">
              <span className="font-mono text-xs uppercase tracking-widest text-neon-cyan">Notifications</span>
              {unreadCount > 0 && (
                <button
                  onClick={markAllRead}
                  className="font-mono text-[11px] uppercase tracking-widest text-slate-400 hover:text-neon-cyan"
                >
                  Mark all read
                </button>
              )}
            </div>
            <div className="max-h-96 overflow-y-auto">
              {query.isLoading && <p className="p-4 font-mono text-xs text-slate-400">Loading…</p>}
              {query.data && query.data.notifications.length === 0 && (
                <p className="p-4 font-mono text-xs text-slate-500">No notifications yet.</p>
              )}
              {query.data?.notifications.map((n) => (
                <button
                  key={n.id}
                  onClick={() => goTo(n)}
                  className={`block w-full border-b border-slate-800 px-4 py-3 text-left transition hover:bg-void/60 ${
                    n.isRead ? "opacity-60" : ""
                  }`}
                >
                  <p className={`font-mono text-xs font-bold ${SEVERITY_CLASS[n.severity] ?? "text-slate-300"}`}>
                    {n.title}
                  </p>
                  <p className="mt-0.5 font-mono text-[11px] text-slate-400">{n.message}</p>
                  <p className="mt-1 font-mono text-[10px] uppercase tracking-widest text-slate-600">
                    {new Date(n.createdAt).toLocaleString()}
                  </p>
                </button>
              ))}
            </div>
          </div>
        </>
      )}

      <div className="pointer-events-none fixed bottom-6 right-6 z-[100] flex flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="pointer-events-auto w-80 cursor-pointer rounded-lg border border-neon-cyan/30 bg-panel/95 p-3 shadow-glow-cyan backdrop-blur"
            onClick={() => {
              setToasts((prev) => prev.filter((x) => x.id !== t.id));
              goTo(t);
            }}
          >
            <p className={`font-mono text-xs font-bold ${SEVERITY_CLASS[t.severity] ?? "text-slate-300"}`}>
              {t.title}
            </p>
            <p className="mt-0.5 font-mono text-[11px] text-slate-400">{t.message}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
