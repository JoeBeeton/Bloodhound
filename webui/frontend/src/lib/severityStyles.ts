import type { Severity } from "./types";

/** Shared across DashboardPage, FindingsPage, and the Findings Feed - three independent copies of
 * the same three maps had already drifted subtly once (see FindingActivityPulse's need for a hex
 * variant, since Recharts fill/stroke props take a literal color, not a Tailwind class) - hoisted
 * here so there's exactly one place to update. */
export const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "text-severity-critical",
  HIGH: "text-severity-high",
  MEDIUM: "text-severity-medium",
  LOW: "text-severity-low",
  INFO: "text-severity-info",
};

export const SEVERITY_ACCENT: Record<Severity, string> = {
  CRITICAL: "border-l-severity-critical",
  HIGH: "border-l-severity-high",
  MEDIUM: "border-l-severity-medium",
  LOW: "border-l-severity-low",
  INFO: "border-l-severity-info",
};

/** Literal hex values matching tailwind.config's `severity.*` tokens - for contexts (Recharts fill/stroke) that can't consume a Tailwind class. */
export const SEVERITY_HEX: Record<Severity, string> = {
  CRITICAL: "#ff2e97",
  HIGH: "#ffb800",
  MEDIUM: "#00f0ff",
  LOW: "#7a8aa0",
  INFO: "#94a3b8",
};
