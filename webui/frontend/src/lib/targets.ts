import { apiFetch } from "./apiClient";
import type { Target } from "./types";

/** Shared by FindingsPage and the Findings Feed page to populate their target-filter dropdowns - includeInactive=true so a since-deactivated target still shows up as a filter option for its (likely historical) findings, same reasoning TargetsPage's own "show removed" toggle uses. */
export async function fetchTargetsForFilter(): Promise<Target[]> {
  const res = await apiFetch("/api/v1/targets?includeInactive=true");
  if (!res.ok) throw new Error("Failed to load targets.");
  return res.json();
}
