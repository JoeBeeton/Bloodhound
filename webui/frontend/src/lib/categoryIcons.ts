import type { FindingCategory } from "./types";

/** One glyph per category for the Findings Feed's timeline cards - a quick visual scan aid, purely decorative (the text label from CATEGORY_LABELS in FindingsFilterBar always renders alongside it, so this never carries meaning on its own). */
export const CATEGORY_ICONS: Record<FindingCategory, string> = {
  EXPOSURE: "🔓",
  TLS: "🔒",
  DNS: "🌐",
  NETWORK: "🛰️",
  HEADERS: "📋",
  SUBDOMAIN_HYGIENE: "🔍",
  WHOIS: "📇",
  BREACH: "💥",
  WEB_APP: "🖥️",
  BRAND: "🏷️",
  COMPOUND: "⚡",
};
