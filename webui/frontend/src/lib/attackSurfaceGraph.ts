import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from "d3-force";
import type { SimulationLinkDatum, SimulationNodeDatum } from "d3-force";
import type { Subdomain, Target, TargetType, WorkerStatus } from "./types";

export type GraphNodeKind = "hub" | "database" | "webui" | "worker" | "target" | "subdomain" | "more";

/** A simulation node - x/y/vx/vy/fx/fy come from SimulationNodeDatum, mutated in place as the simulation runs. */
export interface GraphNode extends SimulationNodeDatum {
  id: string;
  kind: GraphNodeKind;
  label: string;
  targetType?: TargetType;
  grade?: Target["grade"];
  score?: number | null;
  isActive?: boolean;
  hiddenCount?: number;
  workerStatus?: WorkerStatus["status"];
  workerModule?: string | null;
  href?: string;
  radius: number;
}

export type GraphLink = SimulationLinkDatum<GraphNode> & { kind?: "structural" | "scanning" };

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

/** Per-target cap on rendered subdomain nodes - some real targets have tens of thousands of
 * subdomains (confirmed live: one competitor target had 22,761), so this bounds the graph to
 * something a force layout and a browser can actually render smoothly. The gap between what's
 * shown and the real total is always surfaced via a "+N more" ghost node, never silently dropped. */
export const SUBDOMAINS_PER_TARGET_CAP = 14;

const TYPE_COLOR: Record<TargetType, string> = {
  OWN: "#00f0ff",
  COMPETITOR: "#ff2e97",
  WATCHLIST: "#ffb800",
};

/** Platform-node colors are deliberately outside the own/competitor/watchlist palette - the
 * infrastructure running the scans is a different kind of thing from what's being scanned, and
 * should never be visually confusable with a target. */
const PLATFORM_COLOR = "#a78bfa"; // violet - reads as "system", not "target"
const WORKER_STATUS_COLOR: Record<WorkerStatus["status"], string> = {
  IDLE: "#7a8aa0",
  BUSY: "#ffb800",
  OFFLINE: "#3a3a4a",
};

export function colorForTargetType(type: TargetType | undefined): string {
  return type ? TYPE_COLOR[type] : "#7a8aa0";
}

export function colorForNode(node: GraphNode): string {
  if (node.kind === "hub" || node.kind === "database" || node.kind === "webui") return PLATFORM_COLOR;
  if (node.kind === "worker") return WORKER_STATUS_COLOR[node.workerStatus ?? "OFFLINE"];
  return colorForTargetType(node.targetType);
}

/**
 * Pure data shaping: the platform's own topology (central-server, postgres, webui, live
 * workers) plus every tracked target and a capped subdomain sample per target -> one node/link
 * graph. No layout/positioning here - see layoutGraph.
 *
 * <p>central-server is the graph's one true structural hub, matching the real architecture
 * ("only central-server touches Postgres" - see the README): webui, postgres, and every worker
 * all connect to it, and so does every tracked target (the org's own list of things to watch).
 * On top of that structural backbone, a BUSY worker gets a second, distinct "scanning" link
 * straight to whichever target it's currently working (matched by targetId) - a live, literal
 * picture of the platform actively doing something, not just a static topology diagram. A
 * worker busy on another organization's job (targetHostname null - see WorkerPanel's own
 * handling of this) simply gets no scanning link, since there's no node in this org's graph for
 * it to point at.
 */
export function buildGraph(
  targets: Target[],
  subdomainsByTarget: Map<string, { sample: Subdomain[]; total: number }>,
  workers: WorkerStatus[] = [],
): GraphData {
  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];

  const HUB_ID = "hub";
  nodes.push({ id: HUB_ID, kind: "hub", label: "CENTRAL-SERVER", radius: 20 });
  nodes.push({ id: "database", kind: "database", label: "POSTGRES", radius: 11 });
  links.push({ source: HUB_ID, target: "database", kind: "structural" });
  nodes.push({ id: "webui", kind: "webui", label: "WEBUI", radius: 9 });
  links.push({ source: HUB_ID, target: "webui", kind: "structural" });

  for (const worker of workers) {
    const workerNodeId = `worker:${worker.workerId}`;
    nodes.push({
      id: workerNodeId,
      kind: "worker",
      label: worker.workerId,
      workerStatus: worker.status,
      workerModule: worker.moduleType,
      radius: worker.status === "BUSY" ? 8 : 6,
    });
    links.push({ source: HUB_ID, target: workerNodeId, kind: "structural" });
  }

  const targetNodeIds = new Set<string>();
  for (const target of targets) {
    const targetNodeId = `target:${target.id}`;
    targetNodeIds.add(target.id);
    const subdomainInfo = subdomainsByTarget.get(target.id);
    const subdomainCount = subdomainInfo?.total ?? 0;
    nodes.push({
      id: targetNodeId,
      kind: "target",
      label: target.hostname,
      targetType: target.targetType,
      grade: target.grade,
      score: target.overallScore,
      // log-scaled so americanexpress.com's 22,761 subdomains doesn't dwarf everything else on
      // the canvas, while still visibly reading as "bigger surface" than an 11-subdomain target.
      radius: 10 + Math.min(14, Math.log2(subdomainCount + 1) * 2.4),
    });
    links.push({ source: HUB_ID, target: targetNodeId, kind: "structural" });

    const sample = subdomainInfo?.sample ?? [];
    for (const sub of sample) {
      const subNodeId = `sub:${target.id}:${sub.id}`;
      nodes.push({
        id: subNodeId,
        kind: "subdomain",
        label: sub.hostname,
        targetType: target.targetType,
        isActive: sub.isActive,
        radius: sub.isActive ? 5 : 3.5,
      });
      links.push({ source: targetNodeId, target: subNodeId, kind: "structural" });
    }

    const hidden = subdomainCount - sample.length;
    if (hidden > 0) {
      const moreNodeId = `more:${target.id}`;
      nodes.push({
        id: moreNodeId,
        kind: "more",
        label: `+${hidden.toLocaleString()} more`,
        targetType: target.targetType,
        hiddenCount: hidden,
        radius: 4,
      });
      links.push({ source: targetNodeId, target: moreNodeId, kind: "structural" });
    }
  }

  // Live "currently scanning" overlay - a worker whose in-flight job's target is actually in
  // this graph gets a second link straight to it, distinct in kind from the structural ones
  // above so the renderer can style it differently (animated, amber, drawn on top).
  for (const worker of workers) {
    if (worker.status === "BUSY" && worker.targetId && targetNodeIds.has(worker.targetId)) {
      links.push({ source: `worker:${worker.workerId}`, target: `target:${worker.targetId}`, kind: "scanning" });
    }
  }

  return { nodes, links };
}

/** href for a node - kept separate from buildGraph's plain-data node shape so GraphNode doesn't need react-router's types. */
export function hrefForNode(node: GraphNode): string | undefined {
  if (node.kind === "target") {
    const targetId = node.id.slice("target:".length);
    return `/targets/${targetId}`;
  }
  if (node.kind === "subdomain") {
    const [, targetId] = node.id.split(":");
    return `/targets/${targetId}/subdomains/${encodeURIComponent(node.label)}`;
  }
  if (node.kind === "more") {
    const targetId = node.id.slice("more:".length);
    return `/targets/${targetId}/subdomains`;
  }
  return undefined;
}

/**
 * Runs d3-force to completion synchronously and returns the same node array with x/y populated.
 * forceX/forceY per cluster gives the layout real structure instead of a directionless blob:
 * own/competitor/watchlist targets each drift toward their own quadrant, and the platform nodes
 * (central-server, postgres, webui, workers) drift toward a distinct zone of their own - visually
 * separating "the system doing the scanning" from "what's being scanned" - reinforced by the
 * violet/status palette (see colorForNode), not just position.
 */
export function layoutGraph(data: GraphData, width: number, height: number): GraphData {
  const clusterCenters: Record<TargetType, [number, number]> = {
    OWN: [width * 0.32, height * 0.28],
    COMPETITOR: [width * 0.78, height * 0.34],
    WATCHLIST: [width * 0.5, height * 0.85],
  };
  const platformCenter: [number, number] = [width * 0.14, height * 0.78];

  function clusterFor(d: GraphNode): [number, number] {
    if (d.kind === "database" || d.kind === "webui" || d.kind === "worker") return platformCenter;
    if (d.targetType) return clusterCenters[d.targetType];
    return [width / 2, height / 2];
  }

  const simulation = forceSimulation(data.nodes)
    .force(
      "link",
      forceLink<GraphNode, GraphLink>(data.links)
        .id((d) => d.id)
        .distance((l) => {
          if (l.kind === "scanning") return 90;
          const source = l.source as GraphNode;
          return source.kind === "hub" ? 150 : 46;
        })
        .strength((l) => (l.kind === "scanning" ? 0.25 : 0.55)),
    )
    .force("charge", forceManyBody().strength(-90))
    .force("collide", forceCollide<GraphNode>().radius((d) => d.radius + 6))
    .force("center", forceCenter(width / 2, height / 2).strength(0.02))
    .force(
      "x",
      forceX<GraphNode>((d) => clusterFor(d)[0]).strength((d) => (d.kind === "hub" ? 0.15 : 0.06)),
    )
    .force(
      "y",
      forceY<GraphNode>((d) => clusterFor(d)[1]).strength((d) => (d.kind === "hub" ? 0.15 : 0.06)),
    )
    .stop();

  simulation.tick(300);
  return data;
}
