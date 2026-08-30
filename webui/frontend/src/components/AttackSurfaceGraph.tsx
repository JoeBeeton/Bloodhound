import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type WheelEvent as ReactWheelEvent,
} from "react";
import { useNavigate } from "react-router-dom";
import {
  colorForNode,
  colorForTargetType,
  hrefForNode,
  layoutGraph,
  PLATFORM_ENDPOINTS,
  selectNonOverlappingSubdomainLabels,
  truncatedNodeLabel,
  type GraphData,
  type GraphNode,
} from "../lib/attackSurfaceGraph";

const WIDTH = 1200;
const HEIGHT = 720;

/** Subdomain names stay hidden at the default overview zoom - hundreds of them packed around
 * a busy target would be unreadable clutter - and appear once zoomed in past ~1.8x (viewBox
 * width below this), where there's actually room to read them. viewBox.w IS the zoom level
 * here (see handleWheel): it shrinks as you zoom in, grows as you zoom out. */
const SUBDOMAIN_LABEL_ZOOM_THRESHOLD = WIDTH * 0.55;

/** Same min/max zoom bounds handleWheel already clamps manual scroll-to-zoom to - the initial
 * auto-fit (see the mount effect below) reuses them so the starting view never lands somewhere
 * a user couldn't also reach by scrolling. */
const MIN_VIEWBOX_WIDTH = WIDTH * 0.35;
const MAX_VIEWBOX_WIDTH = WIDTH * 2.5;

/** Rough on-screen footprint of the legend overlay (an absolutely-positioned HTML box in the
 * bottom-left corner, outside the SVG coordinate space - see the legend div below), converted to
 * roughly the same svg-unit scale the default 1200x720 viewBox uses. Reserved as extra padding
 * around the bottom-left of the initial auto-fit's bounding box so "zoom in as much as possible"
 * doesn't also mean "sit the legend on top of real nodes." An estimate, not a live measurement -
 * good enough since the legend's own size only changes if someone edits it. */
const LEGEND_RESERVED_LEFT = 170;
const LEGEND_RESERVED_BOTTOM = 140;

/**
 * A product/AppSec review found every node was mouse-only - a plain SVG onClick with no
 * tabIndex, role, or keyboard handler anywhere, so a keyboard-only user had no way to reach any
 * target/subdomain from this page at all (WCAG 2.1.1/4.1.2), despite the map being a real
 * navigation surface (clicking a node routes to its target/subdomain detail page). Only nodes
 * {@link hrefForNode} actually gives a destination to (target/subdomain/"more") are made
 * focusable - the platform nodes (hub/database/webui/worker) aren't links, so giving them
 * role="button" would be a focusable dead end, itself an accessibility anti-pattern.
 */
function ariaLabelForNode(node: GraphNode): string {
  if (node.kind === "target") {
    return `${node.label}, ${node.targetType}${node.grade ? `, grade ${node.grade} (${node.score?.toFixed(0)})` : ", not yet scanned"}`;
  }
  if (node.kind === "subdomain") {
    return `${node.label}, ${node.isActive ? "active" : "inactive"} subdomain`;
  }
  if (node.kind === "more") {
    return `View all subdomains for this target${node.hiddenCount ? ` (${node.hiddenCount} more not shown)` : ""}`;
  }
  return node.label;
}

/**
 * Renders an already-shaped GraphData as a force-directed SVG map: central-server at the hub,
 * the platform's own topology (postgres, webui, live workers) clustered to one side, and every
 * tracked target - with its own discovered subdomains orbiting it in turn - clustered by type
 * elsewhere (see layoutGraph). Positions are computed once per `data` identity (see the useMemo
 * below) via a synchronous d3-force run - no live physics/dragging in this version, which keeps
 * the whole thing simple, fast, and reliably legible rather than jittery. Pan (drag) and zoom
 * (wheel) are implemented directly against the SVG's own viewBox, not a library, since that's
 * all a static, already-laid-out graph needs.
 */
export function AttackSurfaceGraph({ data }: { data: GraphData }) {
  const navigate = useNavigate();
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: WIDTH, h: HEIGHT });
  const dragState = useRef<{ startX: number; startY: number; origX: number; origY: number } | null>(null);
  const [isPanning, setIsPanning] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const laidOut = useMemo(() => layoutGraph(data, WIDTH, HEIGHT), [data]);

  // Auto-fit the starting view to however much of the map actually has content, rather than
  // always opening on the full fixed 1200x720 extent regardless of how sparse or dense the real
  // graph is. Deliberately runs ONCE on mount only (empty deps), not on every `laidOut` change -
  // workersQuery polls every WORKER_POLL_INTERVAL_MS (see AttackSurfaceMapPage), which gives
  // `data`/`laidOut` a new identity on every poll; re-fitting on that cadence would silently
  // reset any pan/zoom the user just did.
  useEffect(() => {
    const svgEl = svgRef.current;
    const positioned = laidOut.nodes.filter(
      (n): n is GraphNode & { x: number; y: number } => n.x != null && n.y != null,
    );
    if (!svgEl || positioned.length === 0) return;

    const LABEL_ROOM = 24; // vertical room below a node for its label text
    const MARGIN = 30;
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    for (const n of positioned) {
      minX = Math.min(minX, n.x - n.radius);
      maxX = Math.max(maxX, n.x + n.radius);
      minY = Math.min(minY, n.y - n.radius);
      maxY = Math.max(maxY, n.y + n.radius + LABEL_ROOM);
    }
    minX -= MARGIN + LEGEND_RESERVED_LEFT;
    minY -= MARGIN;
    maxX += MARGIN;
    maxY += MARGIN + LEGEND_RESERVED_BOTTOM;

    const rect = svgEl.getBoundingClientRect();
    const containerAspect = rect.width > 0 && rect.height > 0 ? rect.width / rect.height : WIDTH / HEIGHT;

    // Expand whichever axis is the tighter constraint so the fitted box matches the container's
    // actual on-screen aspect ratio - the same "meet" behavior preserveAspectRatio gives via
    // letterboxing, computed explicitly here since the viewBox itself is what's being chosen.
    let w = maxX - minX;
    let h = maxY - minY;
    if (w / h > containerAspect) {
      h = w / containerAspect;
    } else {
      w = h * containerAspect;
    }
    w = Math.min(MAX_VIEWBOX_WIDTH, Math.max(MIN_VIEWBOX_WIDTH, w));
    h = w / containerAspect;

    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    setViewBox({ x: cx - w / 2, y: cy - h / 2, w, h });
  }, []);
  const subdomainLabelsVisible = viewBox.w < SUBDOMAIN_LABEL_ZOOM_THRESHOLD;
  // Positions are fixed after layout (see layoutGraph's own comment) so this only needs
  // recomputing when the node set itself changes, not on every zoom/pan.
  const nonOverlappingSubdomainLabelIds = useMemo(
    () => selectNonOverlappingSubdomainLabels(laidOut.nodes),
    [laidOut.nodes],
  );

  const nodesById = useMemo(() => new Map(laidOut.nodes.map((n) => [n.id, n])), [laidOut.nodes]);

  const hoveredNode = hoveredId ? (nodesById.get(hoveredId) ?? null) : null;
  const connectedIds = useMemo(() => {
    if (!hoveredId) return null;
    const ids = new Set<string>([hoveredId]);
    for (const link of laidOut.links) {
      const sourceId = typeof link.source === "string" ? link.source : (link.source as GraphNode).id;
      const targetId = typeof link.target === "string" ? link.target : (link.target as GraphNode).id;
      if (sourceId === hoveredId) ids.add(targetId);
      if (targetId === hoveredId) ids.add(sourceId);
    }
    return ids;
  }, [hoveredId, laidOut.links]);

  function handleWheel(e: ReactWheelEvent<SVGSVGElement>) {
    e.preventDefault();
    const scale = e.deltaY > 0 ? 1.1 : 0.9;
    setViewBox((v) => {
      const newW = Math.min(WIDTH * 2.5, Math.max(WIDTH * 0.35, v.w * scale));
      const newH = newW * (HEIGHT / WIDTH);
      // Zoom toward the pointer, not the viewBox origin, so scroll-to-zoom feels anchored to the cursor.
      const rect = (e.target as SVGSVGElement).getBoundingClientRect();
      const px = (e.clientX - rect.left) / rect.width;
      const py = (e.clientY - rect.top) / rect.height;
      const dx = (v.w - newW) * px;
      const dy = (v.h - newH) * py;
      return { x: v.x + dx, y: v.y + dy, w: newW, h: newH };
    });
  }

  function handleMouseDown(e: ReactMouseEvent<SVGSVGElement>) {
    dragState.current = { startX: e.clientX, startY: e.clientY, origX: viewBox.x, origY: viewBox.y };
    setIsPanning(true);
  }
  function handleMouseMove(e: ReactMouseEvent<SVGSVGElement>) {
    if (!dragState.current) return;
    const scale = viewBox.w / WIDTH;
    const dx = (e.clientX - dragState.current.startX) * scale;
    const dy = (e.clientY - dragState.current.startY) * scale;
    setViewBox((v) => ({ ...v, x: dragState.current!.origX - dx, y: dragState.current!.origY - dy }));
  }
  function endDrag() {
    dragState.current = null;
    setIsPanning(false);
  }

  function handleNodeKeyDown(e: ReactKeyboardEvent<SVGGElement>, href: string) {
    // Enter/Space, the same activation keys a real <button> or <a> respond to - Space is
    // preventDefault'd so it doesn't also scroll the page, same as a native button.
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      navigate(href);
    }
  }

  return (
    <div className="relative w-full overflow-hidden rounded-lg border border-neon-cyan/20 bg-panel/50">
      {/* Marching-ants flow for "currently scanning" links - CSS keyframes scoped here rather
          than a Tailwind utility, since animating stroke-dashoffset on an SVG line has no
          built-in Tailwind equivalent. focus-visible outline is here for the same reason: a
          node is an SVG <g>, not an HTML element, so Tailwind's focus utilities don't apply to
          it - :focus-visible (not :focus) so this only shows for keyboard focus, not a lingering
          ring left over from a mouse click same as every other focus style in this app. */}
      <style>
        {"@keyframes asm-flow { to { stroke-dashoffset: -16; } } " +
          ".asm-node-focusable:focus-visible { outline: 2px solid #00f0ff; outline-offset: 4px; border-radius: 50%; }"}
      </style>
      <svg
        ref={svgRef}
        viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
        className={`h-[70vh] w-full select-none ${isPanning ? "cursor-grabbing" : "cursor-grab"}`}
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={endDrag}
        onMouseLeave={endDrag}
      >
        <defs>
          <filter id="asm-glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="3.2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <radialGradient id="asm-hub-fill" cx="35%" cy="35%" r="65%">
            <stop offset="0%" stopColor="#fff" stopOpacity="0.9" />
            <stop offset="35%" stopColor="#a78bfa" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#6d28d9" stopOpacity="0.85" />
          </radialGradient>
        </defs>

        {/* structural links */}
        <g>
          {laidOut.links.map((link, i) => {
            if (link.kind === "scanning") return null;
            const source = link.source as GraphNode;
            const target = link.target as GraphNode;
            if (typeof source === "string" || typeof target === "string" || source.x == null || target.x == null) {
              return null;
            }
            const dimmed = connectedIds != null && !(connectedIds.has(source.id) && connectedIds.has(target.id));
            const color = target.kind === "database" || target.kind === "webui" || target.kind === "worker"
              ? "#a78bfa"
              : colorForTargetType(target.targetType);
            return (
              <line
                key={i}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={color}
                strokeWidth={source.kind === "hub" ? 1.4 : 0.9}
                opacity={dimmed ? 0.06 : source.kind === "hub" ? 0.45 : 0.28}
              />
            );
          })}
        </g>

        {/* "currently scanning" overlay links - drawn on top, animated, so live activity reads at a glance */}
        <g>
          {laidOut.links.map((link, i) => {
            if (link.kind !== "scanning") return null;
            const source = link.source as GraphNode;
            const target = link.target as GraphNode;
            if (typeof source === "string" || typeof target === "string" || source.x == null || target.x == null) {
              return null;
            }
            const dimmed = connectedIds != null && !(connectedIds.has(source.id) && connectedIds.has(target.id));
            return (
              <line
                key={`scan-${i}`}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke="#ffb800"
                strokeWidth={1.6}
                strokeDasharray="6,4"
                opacity={dimmed ? 0.08 : 0.85}
                style={{ animation: "asm-flow 0.6s linear infinite" }}
                filter="url(#asm-glow)"
              />
            );
          })}
        </g>

        {/* nodes */}
        <g>
          {laidOut.nodes.map((node) => {
            if (node.x == null || node.y == null) return null;
            const dimmed = connectedIds != null && !connectedIds.has(node.id);
            const color = colorForNode(node);
            const href = hrefForNode(node);
            const showLabel =
              node.kind === "hub" ||
              node.kind === "target" ||
              node.kind === "database" ||
              node.kind === "webui" ||
              node.kind === "worker" ||
              (node.kind === "subdomain" && subdomainLabelsVisible && nonOverlappingSubdomainLabelIds.has(node.id)) ||
              hoveredId === node.id;
            const isBusyWorker = node.kind === "worker" && node.workerStatus === "BUSY";
            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                opacity={dimmed ? 0.18 : 1}
                className={`transition-opacity duration-200 ${isBusyWorker ? "animate-pulse" : ""} ${href ? "asm-node-focusable" : ""}`}
                style={{ cursor: href ? "pointer" : "default" }}
                onMouseEnter={() => setHoveredId(node.id)}
                onMouseLeave={() => setHoveredId((cur) => (cur === node.id ? null : cur))}
                onClick={() => href && navigate(href)}
                // Keyboard focus reuses the exact same hoveredId-driven highlight (glow,
                // connected-link emphasis, and the info tooltip) hovering already gives - a
                // keyboard user gets the identical visual feedback a mouse user does, for free,
                // rather than a second bespoke "focused" visual state to keep in sync with it.
                {...(href
                  ? {
                      tabIndex: 0,
                      role: "button",
                      "aria-label": ariaLabelForNode(node),
                      onFocus: () => setHoveredId(node.id),
                      onBlur: () => setHoveredId((cur) => (cur === node.id ? null : cur)),
                      onKeyDown: (e: ReactKeyboardEvent<SVGGElement>) => handleNodeKeyDown(e, href),
                    }
                  : {})}
              >
                <circle
                  r={node.radius}
                  fill={
                    node.kind === "hub"
                      ? "url(#asm-hub-fill)"
                      : node.kind === "more"
                        ? "transparent"
                        : node.isActive === false
                          ? "#1a2233"
                          : color
                  }
                  stroke={node.kind === "more" ? color : node.kind === "database" || node.kind === "webui" ? "#fff" : "none"}
                  strokeDasharray={node.kind === "more" ? "2,2" : undefined}
                  strokeWidth={node.kind === "more" ? 1 : node.kind === "database" || node.kind === "webui" ? 1.2 : 0}
                  strokeOpacity={0.6}
                  filter={
                    node.kind === "hub" ||
                    node.kind === "target" ||
                    node.kind === "database" ||
                    node.kind === "webui" ||
                    isBusyWorker ||
                    hoveredId === node.id
                      ? "url(#asm-glow)"
                      : undefined
                  }
                />
                {node.kind === "target" && (
                  <circle r={node.radius + 4} fill="none" stroke={color} strokeWidth={0.75} opacity={0.35} />
                )}
                {node.kind === "database" && (
                  // A tiny cylinder glyph (two ellipses + a body line) reads as "database" at a glance, without an icon font/library.
                  <g stroke="#12071f" strokeWidth={0.8} fill="none" opacity={0.55}>
                    <ellipse cx={0} cy={-3.5} rx={5.5} ry={2} />
                    <path d="M -5.5,-3.5 L -5.5,3.5 A 5.5,2 0 0 0 5.5,3.5 L 5.5,-3.5" />
                  </g>
                )}
                {showLabel && (
                  <text
                    x={0}
                    y={node.radius + (node.kind === "subdomain" || node.kind === "more" ? 10 : 15)}
                    textAnchor="middle"
                    className="pointer-events-none select-none"
                    style={{
                      fill: node.kind === "hub" ? "#ffffff" : node.kind === "database" || node.kind === "webui" ? "#e9d5ff" : "#cbd5e1",
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: node.kind === "hub" ? 11 : node.kind === "target" ? 9.5 : node.kind === "database" || node.kind === "webui" ? 9 : 8,
                      fontWeight: node.kind === "hub" || node.kind === "target" ? 700 : 400,
                      letterSpacing: node.kind === "hub" ? 2 : 0,
                    }}
                  >
                    {truncatedNodeLabel(node.label)}
                  </text>
                )}
                {/* hostname:port - a small always-visible second line under platform nodes (hub/database/webui/worker), per the request to surface every service's real endpoint on the map. */}
                {showLabel && node.subLabel && (
                  <text
                    x={0}
                    y={node.radius + (node.kind === "subdomain" || node.kind === "more" ? 10 : 15) + (node.kind === "hub" ? 13 : 11)}
                    textAnchor="middle"
                    className="pointer-events-none select-none"
                    style={{
                      fill: "#8b7fc7",
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: node.kind === "hub" ? 9 : 7.5,
                      fontWeight: 400,
                    }}
                  >
                    {node.subLabel}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {hoveredNode && hoveredNode.kind !== "hub" && (
        <div className="pointer-events-none absolute right-3 top-3 max-w-xs rounded border border-neon-cyan/30 bg-void/90 px-3 py-2 font-mono text-xs shadow-glow-cyan">
          <p className="mb-1 font-bold text-slate-100">{hoveredNode.label}</p>
          {hoveredNode.kind === "target" && (
            <p className="text-slate-400">
              <span style={{ color: colorForTargetType(hoveredNode.targetType) }}>{hoveredNode.targetType}</span>
              {hoveredNode.grade && (
                <>
                  {" · "}
                  {hoveredNode.grade} ({hoveredNode.score?.toFixed(0)})
                </>
              )}
            </p>
          )}
          {hoveredNode.kind === "subdomain" && (
            <p className={hoveredNode.isActive ? "text-neon-cyan" : "text-slate-500"}>
              {hoveredNode.isActive ? "active" : "inactive"}
            </p>
          )}
          {hoveredNode.kind === "more" && <p className="text-slate-400">click to view the full list</p>}
          {hoveredNode.kind === "worker" && (
            <>
              <p style={{ color: colorForNode(hoveredNode) }}>
                {hoveredNode.workerStatus}
                {hoveredNode.workerStatus === "BUSY" && hoveredNode.workerModule ? ` · ${hoveredNode.workerModule}` : ""}
              </p>
              {hoveredNode.subLabel && <p className="text-violet-300">{hoveredNode.subLabel}</p>}
              {hoveredNode.fullWorkerId && <p className="text-muted">id: {hoveredNode.fullWorkerId}</p>}
            </>
          )}
          {hoveredNode.kind === "database" && (
            <>
              <p className="text-violet-300">platform service · postgres</p>
              <p className="text-slate-500">internal only, no host port published</p>
            </>
          )}
          {hoveredNode.kind === "webui" && (
            <>
              <p className="text-violet-300">platform service · webui</p>
              {PLATFORM_ENDPOINTS.webui.hostPort && (
                <p className="text-slate-500">
                  published to host as :{PLATFORM_ENDPOINTS.webui.hostPort}
                </p>
              )}
            </>
          )}
        </div>
      )}

      <div className="pointer-events-none absolute bottom-3 left-3 flex flex-col gap-1.5 rounded border border-slate-700/50 bg-void/80 px-3 py-2 font-mono text-[10px] uppercase tracking-widest text-slate-400">
        <LegendRow color="#00f0ff" label="Own" />
        <LegendRow color="#ff2e97" label="Competitor" />
        <LegendRow color="#ffb800" label="Watchlist" />
        <div className="my-0.5 h-px bg-slate-700/60" />
        <LegendRow color="#a78bfa" label="Platform" />
        <LegendRow color="#ffb800" label="Worker busy" />
        <p className="mt-1 text-muted">scroll to zoom · drag to pan</p>
        <p className="text-muted">zoom in to reveal subdomain names</p>
        <p className="text-muted">tab to a node · enter to open it</p>
      </div>
    </div>
  );
}

function LegendRow({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-2">
      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }} />
      {label}
    </span>
  );
}
