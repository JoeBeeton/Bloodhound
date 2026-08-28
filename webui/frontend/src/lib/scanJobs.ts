import type { ScanJobStatus } from "./types";

export interface JobGroup {
  moduleType: string;
  jobs: ScanJobStatus[];
}

/** Tier 2 dispatches one job per authorized host (see ScanRunService#createDeepScan) - a
 * 15-subdomain target's deep scan is 3 modules * 16 hosts = 48 flat rows, which is unreadable
 * as one undifferentiated list anywhere it's rendered (the scan detail page, and the target
 * detail page's inline failure drilldown). Tier 1's one-job-per-module scans (the common case)
 * are unaffected: a group of size 1 renders exactly as a bare row always has. */
export function groupJobsByModule(jobs: ScanJobStatus[]): JobGroup[] {
  const byType = new Map<string, ScanJobStatus[]>();
  for (const j of jobs) {
    const list = byType.get(j.moduleType) ?? [];
    list.push(j);
    byType.set(j.moduleType, list);
  }
  return Array.from(byType.entries()).map(([moduleType, groupJobs]) => ({ moduleType, jobs: groupJobs }));
}
