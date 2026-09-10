import { useEffect, useRef } from "react";

/** Cyan dominates (the app's own primary accent, used for every hover/border/focus state
 * already); magenta and amber only sprinkle in sparingly, matching how those two are already
 * used elsewhere - magenta for occasional emphasis (the "ORG-WIDE" label, dismiss buttons),
 * amber even more rarely (HIGH severity only). Weighted array, not equal thirds, so the field
 * reads as "cyan with the odd accent spark" rather than a generic three-color scatter. */
const CYAN = "#00f0ff";
const COLORS = [CYAN, CYAN, CYAN, CYAN, "#ff2e97", "#ffb800"];

/** One pixel per this many square px of viewport - tuned by eye against the app's own density
 * of on-screen chrome (nav, panels) so the field reads as "ambient texture", not "noise", *and*
 * against the wordmark formation's own needs: every particle is permanent (see the Particle
 * type's own doc comment on why there's no "temporary, removed after" tier), so the ambient
 * field itself has to already contain enough free cyan particles to fully cover the glyph mask
 * (587 points at FORMATION_SAMPLE_STRIDE below, confirmed by sampling it directly) on an
 * ordinary desktop viewport, not just on average. ~800 cyan particles (comfortably above that
 * with margin) at the ~4/6 cyan weighting below needs ~1200 total. */
const AREA_PER_PARTICLE = 1500;
const MAX_PARTICLES = 1200;
const PIXEL_SIZE = 1;

/** The wordmark formation Easter egg - see buildTextMask/tryStartFormation below. */
const FORMATION_FONT_PX = 28;
const FORMATION_SAMPLE_STRIDE = 2;
const FORM_MS = 1800;
const HOLD_MS = 2400;
/** Same duration/easing as FORM_MS - a live design review asked for this to be a smooth return
 * to each particle's own pre-formation position rather than an abrupt resume from wherever it
 * ended up holding, which used to read as the animation "resetting". */
const DISPERSE_MS = 1800;
const MIN_TRIGGER_DELAY_MS = 40_000;
const MAX_TRIGGER_DELAY_MS = 80_000;

interface FormationTarget {
  startX: number;
  startY: number;
  targetX: number;
  targetY: number;
}

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  size: number;
  color: string;
  /** Own phase so twinkle isn't perfectly synchronized across every particle - a field that all
   * pulses in lockstep reads as a glitch, not ambience. */
  twinklePhase: number;
  twinkleSpeed: number;
  /** Non-null while this particle is forming/holding/dispersing as part of a wordmark - see
   * draw()'s formation branch. Normal drift is suspended for exactly this particle while set.
   * Every particle is permanent - a design review specifically asked for no "temporary, created
   * for one formation then removed" tier, so this only ever pauses a real ambient particle's
   * drift, never adds or removes one from the field. */
  formationTarget: FormationTarget | null;
}

function makeParticle(x: number, y: number, color: string): Particle {
  return {
    x,
    y,
    // Slow enough that a full drift across the viewport takes minutes, not seconds - this is
    // meant to read as "alive" at a glance, not as something a viewer consciously tracks moving.
    vx: (Math.random() - 0.5) * 0.08,
    vy: (Math.random() - 0.5) * 0.08,
    size: Math.random() < 0.8 ? PIXEL_SIZE : PIXEL_SIZE * 2,
    color,
    twinklePhase: Math.random() * Math.PI * 2,
    twinkleSpeed: 0.0008 + Math.random() * 0.0012,
    formationTarget: null,
  };
}

function createParticles(width: number, height: number): Particle[] {
  const count = Math.min(MAX_PARTICLES, Math.round((width * height) / AREA_PER_PARTICLE));
  return Array.from({ length: count }, () =>
    makeParticle(Math.random() * width, Math.random() * height, COLORS[Math.floor(Math.random() * COLORS.length)]),
  );
}

interface TextMask {
  points: { dx: number; dy: number }[];
  width: number;
  height: number;
}

/**
 * Renders "BLOODHOUND" to an offscreen canvas once (same Orbitron display font + bold weight as
 * the real header wordmark - see Shell.tsx's own `font-display font-extrabold` logo) and samples
 * its alpha channel for glyph-shaped points, the same "draw it, then read back which pixels are
 * ink" technique the header's own theme-logo-export code uses (see Base.astro's canvas-drawImage
 * step) for an unrelated purpose. Points are stored relative to the text's own center so a
 * formation can be placed anywhere by adding a chosen (cx, cy) - see tryStartFormation.
 */
function buildTextMask(fontPx: number): TextMask {
  const probe = document.createElement("canvas").getContext("2d")!;
  probe.font = `700 ${fontPx}px Orbitron, sans-serif`;
  const text = "BLOODHOUND";
  const textWidth = probe.measureText(text).width;

  const width = Math.ceil(textWidth) + 12;
  const height = Math.ceil(fontPx * 1.5);
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d")!;
  ctx.font = `700 ${fontPx}px Orbitron, sans-serif`;
  ctx.fillStyle = "#fff";
  ctx.textBaseline = "top";
  ctx.fillText(text, 6, fontPx * 0.2);

  const data = ctx.getImageData(0, 0, width, height).data;
  const points: { dx: number; dy: number }[] = [];
  for (let y = 0; y < height; y += FORMATION_SAMPLE_STRIDE) {
    for (let x = 0; x < width; x += FORMATION_SAMPLE_STRIDE) {
      if (data[(y * width + x) * 4 + 3] > 128) {
        points.push({ dx: x - width / 2, dy: y - height / 2 });
      }
    }
  }
  return { points, width, height };
}

/**
 * Picks a random spot for a wordmark formation that stays clear of the central "content" band of
 * the viewport, where every page's actual panels/text live - the whole point of the Easter egg
 * is a quiet surprise in the margins, not something that sits on top of (and fights with) what
 * someone's actually reading. Rejection sampling rather than solving for a valid region directly:
 * simple, and the forbidden band only ever covers the middle of the screen, so a handful of
 * random tries almost always lands outside it when there's room at all. Returns null (caller
 * skips this cycle) if the viewport is too small to fit the text outside that band at all - a
 * narrow/short window has no safe margin, and a formation happening on top of real content would
 * be exactly the wrong outcome.
 */
function pickSafeFormationCenter(
  viewportWidth: number,
  viewportHeight: number,
  maskWidth: number,
  maskHeight: number,
): { x: number; y: number } | null {
  const forbidden = {
    left: viewportWidth * 0.22,
    right: viewportWidth * 0.78,
    top: viewportHeight * 0.14,
    bottom: viewportHeight * 0.86,
  };
  const marginX = maskWidth / 2 + 24;
  const marginY = maskHeight / 2 + 24;
  if (viewportWidth < marginX * 2 || viewportHeight < marginY * 2) {
    return null;
  }
  for (let attempt = 0; attempt < 20; attempt++) {
    const cx = marginX + Math.random() * (viewportWidth - 2 * marginX);
    const cy = marginY + Math.random() * (viewportHeight - 2 * marginY);
    const left = cx - maskWidth / 2;
    const right = cx + maskWidth / 2;
    const top = cy - maskHeight / 2;
    const bottom = cy + maskHeight / 2;
    const overlapsForbidden = left < forbidden.right && right > forbidden.left && top < forbidden.bottom && bottom > forbidden.top;
    if (!overlapsForbidden) {
      return { x: cx, y: cy };
    }
  }
  return null;
}

/**
 * A visual-design pass asked for a particle background matching the retro-synthwave feel
 * omarchy.org uses (scattered pixels drifting over a dark field) - reusing this app's own
 * palette (severity/neon colors) rather than that site's, and small squares rather than smooth
 * dots to match the blocky-pixel motif already established (JetBrains Mono everywhere, the
 * pixel-art mascot). Sits between GridHorizon (the perspective floor/glow) and actual page
 * content in Shell's stacking order - see Shell.tsx.
 *
 * <p>A follow-up ask added the wordmark Easter egg: every minute or so, the cyan particles
 * (only the ones matching the header logo's own color - magenta/amber sit out) briefly
 * assemble into "BLOODHOUND" at a random spot that stays clear of the central content band
 * (see pickSafeFormationCenter), hold for a couple of seconds, then release back into normal
 * drift. Entirely inert under prefers-reduced-motion, same as the drift/twinkle themselves.
 *
 * <p>Canvas + a single imperative rAF loop, not React state per frame - a re-render for every
 * particle every frame would be real, needless cost for a purely decorative layer. Reinitializes
 * on every mount since Shell itself is re-instantiated per page (not a persistent layout - see
 * authBridge.ts's own doc comment on the identical issue for SecurityStatusBanner's dismissal
 * state) - a fresh random scatter (and formation timer) on navigation is imperceptible for
 * ambient background, so this doesn't need the same fix.
 */
export function ParticleBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let particles: Particle[] = [];
    let animationFrame: number | undefined;
    let width = 0;
    let height = 0;
    let cancelled = false;

    let textMask: TextMask | null = null;
    let formationPhase: "idle" | "forming" | "holding" | "dispersing" = "idle";
    let phaseStart = 0;
    let nextTriggerAt = performance.now() + MIN_TRIGGER_DELAY_MS + Math.random() * (MAX_TRIGGER_DELAY_MS - MIN_TRIGGER_DELAY_MS);

    if (!reduceMotion) {
      // Fonts.load/ready first: sampling "BLOODHOUND" before Orbitron has actually downloaded
      // would bake in the fallback font's glyph shapes instead, only fixable by a page reload -
      // exactly the class of bug omarchy.org's own PixelSnap component guards against for its
      // pixel-grid alignment (document.fonts.check) before doing anything shape-sensitive.
      document.fonts
        .load(`700 ${FORMATION_FONT_PX}px Orbitron`)
        .catch(() => {})
        .then(() => document.fonts.ready)
        .catch(() => {})
        .then(() => {
          if (!cancelled) textMask = buildTextMask(FORMATION_FONT_PX);
        });
    }

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas!.width = width * dpr;
      canvas!.height = height * dpr;
      canvas!.style.width = `${width}px`;
      canvas!.style.height = `${height}px`;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);

      if (particles.length === 0) {
        particles = createParticles(width, height);
        return;
      }
      // A resize (common on a tiling WM, where switching workspaces or a layout change fires a
      // real window.resize event) used to discard and recreate the whole field from scratch -
      // which silently threw away any particle mid-formation, contradicting the "every particle
      // is permanent, never removed" guarantee this component exists to uphold (see the Particle
      // type's own doc comment). Reposition anything now outside the new bounds and only grow/
      // shrink the pool to match the new viewport's own budget, instead of wiping it.
      for (const p of particles) {
        if (p.x > width) p.x = Math.random() * width;
        if (p.y > height) p.y = Math.random() * height;
      }
      const targetCount = Math.min(MAX_PARTICLES, Math.round((width * height) / AREA_PER_PARTICLE));
      if (particles.length < targetCount) {
        const extra = Array.from({ length: targetCount - particles.length }, () =>
          makeParticle(Math.random() * width, Math.random() * height, COLORS[Math.floor(Math.random() * COLORS.length)]),
        );
        particles.push(...extra);
      } else if (particles.length > targetCount) {
        // Only ever trims toward a smaller viewport's own density budget, and only from
        // particles not currently part of a formation - never as a way of ending the wordmark
        // effect itself.
        const removable = particles.filter((p) => !p.formationTarget);
        const toRemove = new Set(removable.slice(0, particles.length - targetCount));
        particles = particles.filter((p) => !toRemove.has(p));
      }
    }

    /**
     * Assigns every glyph-mask point a free cyan particle already in the ambient field - see
     * AREA_PER_PARTICLE's own doc comment for why the field is sized to comfortably have enough
     * of them on an ordinary viewport. Subsampling down to whatever's actually free only kicks
     * in as a graceful fallback (a small/narrow window, or an unlucky moment where an unusual
     * number of cyan particles are mid-drift near the edge) - it's never the normal case.
     */
    function tryStartFormation(time: number) {
      if (!textMask || textMask.points.length === 0) return;
      const center = pickSafeFormationCenter(width, height, textMask.width, textMask.height);
      if (!center) return;

      const freeCyan = particles.filter((p) => p.color === CYAN && !p.formationTarget);
      const shuffledParticles = [...freeCyan].sort(() => Math.random() - 0.5);
      const shuffledPoints =
        textMask.points.length <= shuffledParticles.length
          ? textMask.points
          : [...textMask.points].sort(() => Math.random() - 0.5).slice(0, shuffledParticles.length);
      const assignCount = Math.min(shuffledParticles.length, shuffledPoints.length);
      for (let i = 0; i < assignCount; i++) {
        shuffledParticles[i].formationTarget = {
          startX: shuffledParticles[i].x,
          startY: shuffledParticles[i].y,
          targetX: center.x + shuffledPoints[i].dx,
          targetY: center.y + shuffledPoints[i].dy,
        };
      }
      formationPhase = "forming";
      phaseStart = time;
    }

    function draw(time: number) {
      if (!reduceMotion) {
        if (formationPhase === "idle" && time >= nextTriggerAt) {
          tryStartFormation(time);
          if (formationPhase === "idle") {
            // No safe spot this cycle - try again next cycle rather than spinning every frame
            // until one happens to work.
            nextTriggerAt = time + MIN_TRIGGER_DELAY_MS + Math.random() * (MAX_TRIGGER_DELAY_MS - MIN_TRIGGER_DELAY_MS);
          }
        } else if (formationPhase === "forming") {
          const t = Math.min(1, (time - phaseStart) / FORM_MS);
          const eased = 1 - (1 - t) ** 3;
          for (const p of particles) {
            if (p.formationTarget) {
              p.x = p.formationTarget.startX + (p.formationTarget.targetX - p.formationTarget.startX) * eased;
              p.y = p.formationTarget.startY + (p.formationTarget.targetY - p.formationTarget.startY) * eased;
            }
          }
          if (t >= 1) {
            formationPhase = "holding";
            phaseStart = time;
          }
        } else if (formationPhase === "holding" && time - phaseStart >= HOLD_MS) {
          formationPhase = "dispersing";
          phaseStart = time;
        } else if (formationPhase === "dispersing") {
          // The reverse of "forming" - ease from the held target position back to wherever this
          // particle actually started, instead of just clearing formationTarget and letting
          // normal drift resume from the hold point, which read as the word "resetting" rather
          // than gracefully dissolving (see this constant's own doc comment).
          const t = Math.min(1, (time - phaseStart) / DISPERSE_MS);
          const eased = 1 - (1 - t) ** 3;
          for (const p of particles) {
            if (p.formationTarget) {
              const { startX, startY, targetX, targetY } = p.formationTarget;
              p.x = targetX + (startX - targetX) * eased;
              p.y = targetY + (startY - targetY) * eased;
            }
          }
          if (t >= 1) {
            for (const p of particles) p.formationTarget = null;
            formationPhase = "idle";
            nextTriggerAt = time + MIN_TRIGGER_DELAY_MS + Math.random() * (MAX_TRIGGER_DELAY_MS - MIN_TRIGGER_DELAY_MS);
          }
        }
      }

      ctx!.clearRect(0, 0, width, height);
      for (const p of particles) {
        if (!reduceMotion && !p.formationTarget) {
          p.x = (p.x + p.vx + width) % width;
          p.y = (p.y + p.vy + height) % height;
        }
        const twinkle = reduceMotion ? 0.6 : 0.35 + 0.35 * Math.sin(time * p.twinkleSpeed + p.twinklePhase);
        ctx!.globalAlpha = p.formationTarget ? Math.max(twinkle, 0.75) : twinkle;
        ctx!.fillStyle = p.color;
        ctx!.fillRect(p.x, p.y, p.size, p.size);
      }
      if (!reduceMotion) {
        animationFrame = requestAnimationFrame(draw);
      }
    }

    resize();
    draw(0);
    if (reduceMotion) {
      // Static field: still redraw on resize so it doesn't get bleached into stale, off-canvas
      // positions, but no rAF loop (and no formation attempts) runs.
      const onResize = () => {
        resize();
        draw(0);
      };
      window.addEventListener("resize", onResize);
      return () => window.removeEventListener("resize", onResize);
    }

    let resizeTimer: number | undefined;
    const onResize = () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(resize, 150);
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelled = true;
      if (animationFrame !== undefined) cancelAnimationFrame(animationFrame);
      window.clearTimeout(resizeTimer);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0"
    />
  );
}
