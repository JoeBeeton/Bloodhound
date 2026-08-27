import { useMemo, useRef, useState, type MouseEvent as ReactMouseEvent, type WheelEvent as ReactWheelEvent } from "react";
import { useNavigate } from "react-router-dom";
import { colorForTargetType, hrefForNode, layoutGraph, type GraphData, type GraphNode } from "../lib/attackSurfaceGraph";

const WIDTH = 1200;
const HEIGHT = 720;

/**
 * Renders an already-shaped GraphData as a force-directed SVG map: org hub at the center,
 * targets orbiting it (loosely clustered by type - see layoutGraph), and each target's
 * discovered subdomains orbiting it in turn. Positions are computed once per `data` identity
 * (see the useMemo below) via a synchronous d3-force run - no live physics/dragging in this
 * first version, which keeps the whole thing simple, fast, and reliably legible rather than
 * jittery. Pan (drag) and zoom (wheel) are implemented directly against the SVG's own viewBox,
 * not a library, since that's all a static, already-laid-out graph needs.
 */
export function AttackSurfaceGraph({ data }: { data: GraphData }) {
  const navigate = useNavigate();
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: WIDTH, h: HEIGHT });
  const dragState = useRef<{ startX: number; startY: number; origX: number; origY: number } | null>(null);
  const [isPanning, setIsPanning] = useState(false);

  const laidOut = useMemo(() => layoutGraph(data, WIDTH, HEIGHT), [data]);

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

  return (
    <div className="relative w-full overflow-hidden rounded-lg border border-neon-cyan/20 bg-panel/50">
      <svg
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
          <radialGradient id="asm-org-fill" cx="35%" cy="35%" r="65%">
            <stop offset="0%" stopColor="#fff" stopOpacity="0.9" />
            <stop offset="35%" stopColor="#00f0ff" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#ff2e97" stopOpacity="0.85" />
          </radialGradient>
        </defs>

        {/* links */}
        <g>
          {laidOut.links.map((link, i) => {
            const source = link.source as GraphNode;
            const target = link.target as GraphNode;
            if (typeof source === "string" || typeof target === "string" || source.x == null || target.x == null) {
              return null;
            }
            const dimmed = connectedIds != null && !(connectedIds.has(source.id) && connectedIds.has(target.id));
            const color = colorForTargetType(target.targetType);
            return (
              <line
                key={i}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={color}
                strokeWidth={source.kind === "org" ? 1.4 : 0.9}
                opacity={dimmed ? 0.06 : source.kind === "org" ? 0.45 : 0.28}
              />
            );
          })}
        </g>

        {/* nodes */}
        <g>
          {laidOut.nodes.map((node) => {
            if (node.x == null || node.y == null) return null;
            const dimmed = connectedIds != null && !connectedIds.has(node.id);
            const color = node.kind === "org" ? "#ffffff" : colorForTargetType(node.targetType);
            const href = hrefForNode(node);
            const showLabel = node.kind === "org" || node.kind === "target" || hoveredId === node.id;
            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                opacity={dimmed ? 0.18 : 1}
                className="transition-opacity duration-200"
                style={{ cursor: href ? "pointer" : "default" }}
                onMouseEnter={() => setHoveredId(node.id)}
                onMouseLeave={() => setHoveredId((cur) => (cur === node.id ? null : cur))}
                onClick={() => href && navigate(href)}
              >
                <circle
                  r={node.radius}
                  fill={
                    node.kind === "org"
                      ? "url(#asm-org-fill)"
                      : node.kind === "more"
                        ? "transparent"
                        : node.isActive === false
                          ? "#1a2233"
                          : color
                  }
                  stroke={node.kind === "more" ? color : "none"}
                  strokeDasharray={node.kind === "more" ? "2,2" : undefined}
                  strokeWidth={node.kind === "more" ? 1 : 0}
                  filter={node.kind === "org" || node.kind === "target" || hoveredId === node.id ? "url(#asm-glow)" : undefined}
                />
                {node.kind === "target" && (
                  <circle r={node.radius + 4} fill="none" stroke={color} strokeWidth={0.75} opacity={0.35} />
                )}
                {showLabel && (
                  <text
                    x={0}
                    y={node.radius + (node.kind === "subdomain" || node.kind === "more" ? 10 : 15)}
                    textAnchor="middle"
                    className="pointer-events-none select-none"
                    style={{
                      fill: node.kind === "org" ? "#ffffff" : "#cbd5e1",
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: node.kind === "org" ? 11 : node.kind === "target" ? 9.5 : 8,
                      fontWeight: node.kind === "org" || node.kind === "target" ? 700 : 400,
                      letterSpacing: node.kind === "org" ? 2 : 0,
                    }}
                  >
                    {node.label.length > 28 ? node.label.slice(0, 26) + "…" : node.label}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {hoveredNode && hoveredNode.kind !== "org" && (
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
        </div>
      )}

      <div className="pointer-events-none absolute bottom-3 left-3 flex flex-col gap-1.5 rounded border border-slate-700/50 bg-void/80 px-3 py-2 font-mono text-[10px] uppercase tracking-widest text-slate-400">
        <LegendRow color="#00f0ff" label="Own" />
        <LegendRow color="#ff2e97" label="Competitor" />
        <LegendRow color="#ffb800" label="Watchlist" />
        <p className="mt-1 text-slate-600">scroll to zoom · drag to pan</p>
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
