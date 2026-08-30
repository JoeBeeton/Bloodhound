import { useEffect, useRef } from "react";

const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "wheel", "scroll", "touchstart"] as const;
const CHECK_INTERVAL_MS = 5_000;

/**
 * Forces a logout after a period of genuine user inactivity, not just an open tab.
 *
 * A product/AppSec review found this app had no idle-session timeout at all, despite its own
 * design implying one: a 15-minute access token that silently re-authenticates via a refresh
 * cookie on the next request. In principle that should mean an abandoned tab goes quiet within
 * ~15 minutes. In practice it never did - NotificationCenter polls unconditionally every 25s on
 * every authenticated page, which keeps triggering that silent refresh regardless of whether a
 * real person is at the keyboard. A shared computer, a stolen unlocked laptop, or a forgotten
 * public terminal stayed fully authenticated indefinitely - up to the 90-day absolute session
 * cap - with zero actual interaction required.
 *
 * Tracks real activity via DOM events on window (mouse/keyboard/touch/scroll/wheel), not React
 * state - state would cause a re-render, and thus reschedule every consumer's effects, on every
 * single mouse move, which is not something to do 60+ times a second. A plain interval instead
 * polls the last-activity timestamp every few seconds and fires onWarn/onTimeout as thresholds
 * are crossed - cheap, and correctly self-resets if activity resumes.
 */
export function useIdleLogout({
  enabled,
  idleTimeoutMs,
  warningMs,
  onWarn,
  onTimeout,
}: {
  enabled: boolean;
  idleTimeoutMs: number;
  warningMs: number;
  onWarn: () => void;
  onTimeout: () => void;
}) {
  const onWarnRef = useRef(onWarn);
  const onTimeoutRef = useRef(onTimeout);
  onWarnRef.current = onWarn;
  onTimeoutRef.current = onTimeout;

  useEffect(() => {
    if (!enabled) return;

    let lastActivityAt = Date.now();
    let warned = false;

    function resetActivity() {
      lastActivityAt = Date.now();
      warned = false;
    }

    ACTIVITY_EVENTS.forEach((event) => window.addEventListener(event, resetActivity, { passive: true }));

    const interval = window.setInterval(() => {
      const idleFor = Date.now() - lastActivityAt;
      if (idleFor >= idleTimeoutMs) {
        onTimeoutRef.current();
      } else if (!warned && idleFor >= idleTimeoutMs - warningMs) {
        warned = true;
        onWarnRef.current();
      }
    }, CHECK_INTERVAL_MS);

    return () => {
      ACTIVITY_EVENTS.forEach((event) => window.removeEventListener(event, resetActivity));
      window.clearInterval(interval);
    };
  }, [enabled, idleTimeoutMs, warningMs]);
}
