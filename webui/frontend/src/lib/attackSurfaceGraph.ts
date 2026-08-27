import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from "d3-force";
import type { SimulationLinkDatum, SimulationNodeDatum } from "d3-force";
import type { Subdomain, Target, TargetType } from "./types";

export type GraphNodeKind = "org" | "target" | "subdomain" | "more";

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
  href?: string;
  radius: number;
}

export type GraphLink = SimulationLinkDatum<GraphNode>;

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

export function colorForTargetType(type: TargetType | undefined): string {
  return type ? TYPE_COLOR[type] : "#7a8aa0";
}

/** Pure data shaping: targets + a capped subdomain sample per target -> a node/link graph. No layout/positioning here - see layoutGraph. */
export function buildGraph(
  targets: Target[],
  subdomainsByTarget: Map<string, { sample: Subdomain[]; total: number }>,
): GraphData {
  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];

  nodes.push({ id: "org", kind: "org", label: "YOUR ORG", radius: 22 });

  for (const target of targets) {
    const targetNodeId = `target:${target.id}`;
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
    links.push({ source: "org", target: targetNodeId });

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
      links.push({ source: targetNodeId, target: subNodeId });
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
      links.push({ source: targetNodeId, target: moreNodeId });
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
 * forceX/forceY per target type gives the layout a loose three-way clustering (own/competitor/
 * watchlist each drift toward their own quadrant) instead of a directionless blob, so the type
 * color-coding is reinforced by position, not just color.
 */
export function layoutGraph(data: GraphData, width: number, height: number): GraphData {
  const clusterCenters: Record<TargetType, [number, number]> = {
    OWN: [width * 0.28, height * 0.32],
    COMPETITOR: [width * 0.74, height * 0.42],
    WATCHLIST: [width * 0.42, height * 0.78],
  };

  const simulation = forceSimulation(data.nodes)
    .force(
      "link",
      forceLink<GraphNode, GraphLink>(data.links)
        .id((d) => d.id)
        .distance((l) => {
          const source = l.source as GraphNode;
          return source.kind === "org" ? 160 : 46;
        })
        .strength(0.55),
    )
    .force("charge", forceManyBody().strength(-90))
    .force("collide", forceCollide<GraphNode>().radius((d) => d.radius + 6))
    .force("center", forceCenter(width / 2, height / 2).strength(0.02))
    .force(
      "x",
      forceX<GraphNode>((d) => (d.targetType ? clusterCenters[d.targetType][0] : width / 2)).strength((d) =>
        d.kind === "org" ? 0.15 : 0.06,
      ),
    )
    .force(
      "y",
      forceY<GraphNode>((d) => (d.targetType ? clusterCenters[d.targetType][1] : height / 2)).strength((d) =>
        d.kind === "org" ? 0.15 : 0.06,
      ),
    )
    .stop();

  simulation.tick(300);
  return data;
}
