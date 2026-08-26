/** Shared between the add-target form and the target-detail schedule control. Daily (86400s) matches the server-side default for a newly-created target. */
export const SCHEDULE_OPTIONS: { label: string; seconds: number }[] = [
  { label: "Every 6 hours", seconds: 6 * 3600 },
  { label: "Every 12 hours", seconds: 12 * 3600 },
  { label: "Daily", seconds: 24 * 3600 },
  { label: "Every 3 days", seconds: 3 * 24 * 3600 },
  { label: "Weekly", seconds: 7 * 24 * 3600 },
];

export const DEFAULT_SCHEDULE_SECONDS = 24 * 3600;

export function scheduleLabel(seconds: number): string {
  return SCHEDULE_OPTIONS.find((o) => o.seconds === seconds)?.label ?? `Every ${Math.round(seconds / 3600)}h`;
}
