/**
 * Perspective grid-horizon backdrop — the shared synthwave motif reused
 * behind hero/dashboard sections in later screens, established here.
 */
export function GridHorizon() {
  return (
    <div
      aria-hidden
      className="pointer-events-none fixed inset-0 overflow-hidden"
    >
      {/* horizon glow */}
      <div
        className="absolute left-1/2 top-[55%] h-[40vh] w-[140vw] -translate-x-1/2 rounded-[100%]"
        style={{
          background:
            "radial-gradient(ellipse at center, rgba(255,46,151,0.35) 0%, rgba(0,240,255,0.12) 35%, transparent 70%)",
          filter: "blur(40px)",
        }}
      />
      {/* perspective grid */}
      <div
        className="absolute inset-x-0 bottom-0 h-[55vh]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,240,255,0.35) 1px, transparent 1px), linear-gradient(90deg, rgba(0,240,255,0.35) 1px, transparent 1px)",
          backgroundSize: "60px 60px",
          transform: "perspective(300px) rotateX(60deg)",
          transformOrigin: "bottom",
          maskImage: "linear-gradient(to top, black, transparent)",
          WebkitMaskImage: "linear-gradient(to top, black, transparent)",
        }}
      />
      {/* scanline texture */}
      <div
        className="absolute inset-0 opacity-[0.06]"
        style={{
          backgroundImage:
            "repeating-linear-gradient(to bottom, #fff 0px, #fff 1px, transparent 1px, transparent 3px)",
        }}
      />
    </div>
  );
}
