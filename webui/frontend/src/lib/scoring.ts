import type { ScoreCategory } from "./types";

/** Mirrors ScoringEngine.CATEGORY_WEIGHTS on the backend exactly. */
export const CATEGORY_WEIGHTS: Record<ScoreCategory, number> = {
  EXPOSURE: 0.22,
  TLS: 0.17,
  DNS: 0.17,
  NETWORK: 0.13,
  HEADERS: 0.08,
  SUBDOMAIN_HYGIENE: 0.08,
  WEB_APP: 0.15,
};

/**
 * Finding categories that exist (FINDING_CATEGORIES in types.ts) but have no slot in
 * CATEGORY_WEIGHTS above, so ScoreImpactCalculator short-circuits them to
 * ScoreImpact.notApplicable - each one describes something other than the target's
 * own infrastructure security posture, which is what the score is defined to measure.
 */
export const UNSCORED_CATEGORY_REASON: Record<string, string> = {
  WHOIS: "Registration/registrar metadata, not a fact about the target's own security posture.",
  BREACH: "Breach-corpus email matches - about people associated with the target, not its infrastructure.",
  BRAND: "Lookalike/typosquat domains and impersonating apps - infrastructure outside the target's own control.",
  COMPOUND: "A derived risk chain built from other findings - scoring it too would double-count them.",
};

/** The tooltip explanation shown for a finding whose ScoreImpact.affectsScore is false. */
export function unscoredCategoryExplanation(category: string): string {
  return (
    UNSCORED_CATEGORY_REASON[category] ??
    "This finding's category isn't part of the overall score."
  );
}
