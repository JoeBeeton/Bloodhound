import { useEffect } from "react";

const DEFAULT_TITLE = "Bloodhound — Attack Surface Monitoring";

/**
 * A product/UX review found every single route showed the exact same static browser-tab title -
 * for a tool this app's own users actually run with many tabs open at once (monitoring several
 * targets, comparing scan runs side by side), that makes the tab bar useless for telling them
 * apart. Pass a specific value where one's meaningful (a hostname, a scan's target) and it takes
 * priority over the page's own generic label - see TargetDetailPage/ScanDetailPage for that
 * pattern. Restores the default on unmount so a page that doesn't set one (or navigating away
 * entirely) never leaves a stale title from whatever page was open before it.
 */
export function usePageTitle(title: string | null | undefined) {
  useEffect(() => {
    document.title = title ? `${title} — Bloodhound` : DEFAULT_TITLE;
    return () => {
      document.title = DEFAULT_TITLE;
    };
  }, [title]);
}
