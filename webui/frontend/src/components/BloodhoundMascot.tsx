import type { CSSProperties } from "react";
import mascotHead from "../assets/bloodhound-mascot-head.webp";
import mascotFull from "../assets/bloodhound-mascot-full.webp";

type MascotProps = {
  className?: string;
  style?: CSSProperties;
  title?: string;
  /**
   * "compact" (default): a tight head/shoulders crop — use for the favicon and
   * nav-header icon, anywhere the mascot sits in a small square-ish slot.
   * "full": the complete seated cyber-hound, real anatomy (four legs, paws, ears,
   * tail) — for spacious placements (e.g. the login hero) where the whole pose has
   * room to read. Portrait aspect ratio (904x1408) — size by height, not a fixed square.
   */
  variant?: "compact" | "full";
};

/**
 * The Bloodhound mascot. Source art is a real generated image (not hand-coded SVG —
 * three prior rounds of freehand vector illustration couldn't get a genuinely
 * anatomical, non-abstract result), background-removed and cropped into two variants.
 * Glow is applied by the caller via a wrapping `drop-shadow` filter, which works the
 * same on an `<img>` as it did on the old inline SVG (it follows the alpha channel).
 */
export function BloodhoundMascot({ className, style, title, variant = "compact" }: MascotProps) {
  const src = variant === "full" ? mascotFull : mascotHead;
  return (
    <img
      src={src}
      alt={title ?? ""}
      role={title ? "img" : "presentation"}
      aria-hidden={title ? undefined : true}
      className={className}
      style={{ objectFit: "contain", ...style }}
    />
  );
}
