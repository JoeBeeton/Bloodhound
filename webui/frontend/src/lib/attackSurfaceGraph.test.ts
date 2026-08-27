import { describe, expect, it } from "vitest";
import { buildGraph, colorForTargetType, hrefForNode, SUBDOMAINS_PER_TARGET_CAP } from "./attackSurfaceGraph";
import type { Subdomain, Target } from "./types";

function target(overrides: Partial<Target> = {}): Target {
  return {
    id: "t1",
    hostname: "example.com",
    targetType: "OWN",
    authorizationStatus: "UNAUTHORIZED",
    scanCadenceSeconds: 3600,
    nextScanAt: "2026-01-01T00:00:00Z",
    isActive: true,
    createdAt: "2026-01-01T00:00:00Z",
    overallScore: 80,
    grade: "B",
    tier1OverallScore: 80,
    tier1Grade: "B",
    ...overrides,
  };
}

function sub(id: string, hostname: string, isActive = true): Subdomain {
  return {
    id,
    hostname,
    firstSeenAt: "2026-01-01T00:00:00Z",
    lastSeenAt: "2026-01-01T00:00:00Z",
    source: "crt.sh",
    isActive,
    currentIpAddresses: [],
  };
}

describe("buildGraph", () => {
  it("always includes exactly one org root node", () => {
    const graph = buildGraph([], new Map());
    expect(graph.nodes.filter((n) => n.kind === "org")).toHaveLength(1);
  });

  it("one target with no subdomains produces just the org and target nodes, linked", () => {
    const t = target();
    const graph = buildGraph([t], new Map([[t.id, { sample: [], total: 0 }]]));

    expect(graph.nodes).toHaveLength(2);
    expect(graph.nodes.map((n) => n.kind)).toEqual(expect.arrayContaining(["org", "target"]));
    expect(graph.links).toHaveLength(1);
    expect(graph.links[0]).toEqual({ source: "org", target: "target:t1" });
  });

  it("subdomains within the cap all become nodes, no ghost node needed", () => {
    const t = target();
    const subs = [sub("s1", "a.example.com"), sub("s2", "b.example.com")];
    const graph = buildGraph([t], new Map([[t.id, { sample: subs, total: 2 }]]));

    const subdomainNodes = graph.nodes.filter((n) => n.kind === "subdomain");
    expect(subdomainNodes).toHaveLength(2);
    expect(graph.nodes.some((n) => n.kind === "more")).toBe(false);
  });

  it("a target whose real subdomain count exceeds the sample gets a ghost 'more' node carrying the true hidden count", () => {
    const t = target();
    const sample = Array.from({ length: SUBDOMAINS_PER_TARGET_CAP }, (_, i) => sub(`s${i}`, `h${i}.example.com`));
    const graph = buildGraph([t], new Map([[t.id, { sample, total: 22761 }]]));

    const more = graph.nodes.find((n) => n.kind === "more");
    expect(more).toBeDefined();
    expect(more!.hiddenCount).toBe(22761 - SUBDOMAINS_PER_TARGET_CAP);
    expect(more!.label).toContain("22,747");
  });

  it("every subdomain and 'more' node inherits its parent target's type, for consistent color-coding", () => {
    const t = target({ id: "t1", targetType: "COMPETITOR" });
    const sample = Array.from({ length: SUBDOMAINS_PER_TARGET_CAP }, (_, i) => sub(`s${i}`, `h${i}.example.com`));
    const graph = buildGraph([t], new Map([[t.id, { sample, total: 100 }]]));

    for (const node of graph.nodes) {
      if (node.kind === "subdomain" || node.kind === "more") {
        expect(node.targetType).toBe("COMPETITOR");
      }
    }
  });

  it("an inactive subdomain gets a smaller radius than an active one", () => {
    const t = target();
    const subs = [sub("s1", "active.example.com", true), sub("s2", "dead.example.com", false)];
    const graph = buildGraph([t], new Map([[t.id, { sample: subs, total: 2 }]]));

    const active = graph.nodes.find((n) => n.id === "sub:t1:s1")!;
    const inactive = graph.nodes.find((n) => n.id === "sub:t1:s2")!;
    expect(inactive.radius).toBeLessThan(active.radius);
  });

  it("multiple targets each get their own independent subtree, no cross-links", () => {
    const t1 = target({ id: "t1", hostname: "a.com" });
    const t2 = target({ id: "t2", hostname: "b.com" });
    const graph = buildGraph(
      [t1, t2],
      new Map([
        ["t1", { sample: [sub("s1", "x.a.com")], total: 1 }],
        ["t2", { sample: [sub("s2", "y.b.com")], total: 1 }],
      ]),
    );

    expect(graph.nodes.filter((n) => n.kind === "target")).toHaveLength(2);
    expect(graph.links).toHaveLength(4); // org->t1, org->t2, t1->s1, t2->s2
    expect(graph.links.some((l) => l.source === "target:t1" && l.target === "sub:t2:s2")).toBe(false);
  });

  it("a bigger subdomain count produces a larger (but bounded) target radius", () => {
    const small = target({ id: "small" });
    const big = target({ id: "big" });
    const graph = buildGraph(
      [small, big],
      new Map([
        ["small", { sample: [], total: 2 }],
        ["big", { sample: [], total: 22761 }],
      ]),
    );

    const smallNode = graph.nodes.find((n) => n.id === "target:small")!;
    const bigNode = graph.nodes.find((n) => n.id === "target:big")!;
    expect(bigNode.radius).toBeGreaterThan(smallNode.radius);
    expect(bigNode.radius).toBeLessThanOrEqual(24); // 10 base + 14 cap
  });
});

describe("colorForTargetType", () => {
  it("returns a distinct color per target type", () => {
    const own = colorForTargetType("OWN");
    const competitor = colorForTargetType("COMPETITOR");
    const watchlist = colorForTargetType("WATCHLIST");
    expect(new Set([own, competitor, watchlist]).size).toBe(3);
  });

  it("falls back to a neutral color when no type is given (the org root node)", () => {
    expect(colorForTargetType(undefined)).toBe("#7a8aa0");
  });
});

describe("hrefForNode", () => {
  it("links a target node to its detail page", () => {
    expect(hrefForNode({ id: "target:abc", kind: "target", label: "x", radius: 10 })).toBe("/targets/abc");
  });

  it("links a subdomain node to its own detail page under the right target", () => {
    expect(
      hrefForNode({ id: "sub:abc:xyz", kind: "subdomain", label: "foo.example.com", radius: 5 }),
    ).toBe("/targets/abc/subdomains/foo.example.com");
  });

  it("links a 'more' ghost node to the target's full subdomain list", () => {
    expect(hrefForNode({ id: "more:abc", kind: "more", label: "+5 more", radius: 4 })).toBe(
      "/targets/abc/subdomains",
    );
  });

  it("the org root node has no href - nothing to navigate to", () => {
    expect(hrefForNode({ id: "org", kind: "org", label: "YOUR ORG", radius: 22 })).toBeUndefined();
  });
});
