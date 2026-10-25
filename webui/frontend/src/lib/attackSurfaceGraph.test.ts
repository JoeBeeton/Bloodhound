import { describe, expect, it } from "vitest";
import {
  buildGraph,
  colorForNode,
  colorForTargetType,
  hrefForNode,
  layoutGraph,
  selectNonOverlappingSubdomainLabels,
  SUBDOMAINS_PER_TARGET_CAP,
} from "./attackSurfaceGraph";
import type { GraphNode } from "./attackSurfaceGraph";
import type { Subdomain, Target, TargetType, WorkerStatus } from "./types";

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
    lastScanAt: null,
    lastScanWasDeep: null,
    notes: null,
    wafVendor: null,
    wafScanned: false,
    estimatedScanDurationSeconds: null,
    ...overrides,
  };
}

function sub(id: string, hostname: string, isActive = true, wafOverrides: Partial<Pick<Subdomain, "wafVendor" | "wafScanned">> = {}): Subdomain {
  return {
    id,
    hostname,
    firstSeenAt: "2026-01-01T00:00:00Z",
    lastSeenAt: "2026-01-01T00:00:00Z",
    source: "crt.sh",
    isActive,
    currentIpAddresses: [],
    wafVendor: null,
    wafScanned: false,
    tlsGrade: null,
    tlsGradeFactors: [],
    ...wafOverrides,
  };
}

function worker(overrides: Partial<WorkerStatus> = {}): WorkerStatus {
  return {
    workerId: "worker-1",
    status: "IDLE",
    lastHeartbeatAt: "2026-01-01T00:00:00Z",
    targetId: null,
    targetHostname: null,
    moduleType: null,
    currentHost: null,
    ...overrides,
  };
}

/** Every buildGraph() call always carries these three platform nodes - asserted once here so the rest of the suite can focus on what varies. */
function expectAlwaysPresentPlatformNodes(nodes: ReturnType<typeof buildGraph>["nodes"]) {
  expect(nodes.filter((n) => n.kind === "hub")).toHaveLength(1);
  expect(nodes.filter((n) => n.kind === "database")).toHaveLength(1);
  expect(nodes.filter((n) => n.kind === "webui")).toHaveLength(1);
}

describe("buildGraph", () => {
  it("always includes the central-server hub, postgres, and webui nodes, linked to the hub, even with nothing else", () => {
    const graph = buildGraph([], new Map());
    expectAlwaysPresentPlatformNodes(graph.nodes);
    expect(graph.links).toEqual(
      expect.arrayContaining([
        { source: "hub", target: "database", kind: "structural" },
        { source: "hub", target: "webui", kind: "structural" },
      ]),
    );
  });

  it("one target with no subdomains produces the platform nodes plus one target node, linked to the hub", () => {
    const t = target();
    const graph = buildGraph([t], new Map([[t.id, { sample: [], total: 0 }]]));

    expectAlwaysPresentPlatformNodes(graph.nodes);
    expect(graph.nodes.filter((n) => n.kind === "target")).toHaveLength(1);
    expect(graph.links).toContainEqual({ source: "hub", target: "target:t1", kind: "structural" });
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

  it("a subdomain's WAF vendor/scanned status carries straight through onto its node", () => {
    const t = target();
    const subs = [
      sub("s1", "protected.example.com", true, { wafVendor: "cloudflare", wafScanned: true }),
      sub("s2", "unprotected.example.com", true, { wafVendor: null, wafScanned: true }),
      sub("s3", "unscanned.example.com", true, { wafVendor: null, wafScanned: false }),
    ];
    const graph = buildGraph([t], new Map([[t.id, { sample: subs, total: 3 }]]));

    expect(graph.nodes.find((n) => n.id === "sub:t1:s1")).toMatchObject({ wafVendor: "cloudflare", wafScanned: true });
    expect(graph.nodes.find((n) => n.id === "sub:t1:s2")).toMatchObject({ wafVendor: null, wafScanned: true });
    expect(graph.nodes.find((n) => n.id === "sub:t1:s3")).toMatchObject({ wafVendor: null, wafScanned: false });
  });

  it("a target's own WAF vendor/scanned status carries through onto its node", () => {
    const t = target({ wafVendor: "akamai", wafScanned: true });
    const graph = buildGraph([t], new Map());

    expect(graph.nodes.find((n) => n.id === "target:t1")).toMatchObject({ wafVendor: "akamai", wafScanned: true });
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
    expect(graph.links).toContainEqual({ source: "hub", target: "target:t1", kind: "structural" });
    expect(graph.links).toContainEqual({ source: "hub", target: "target:t2", kind: "structural" });
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

  it("every live worker becomes its own node, linked to the hub", () => {
    const workers = [worker({ workerId: "w1" }), worker({ workerId: "w2", status: "OFFLINE" })];
    const graph = buildGraph([], new Map(), workers);

    const workerNodes = graph.nodes.filter((n) => n.kind === "worker");
    expect(workerNodes.map((n) => n.id)).toEqual(["worker:w1", "worker:w2"]);
    expect(graph.links).toContainEqual({ source: "hub", target: "worker:w1", kind: "structural" });
    expect(graph.links).toContainEqual({ source: "hub", target: "worker:w2", kind: "structural" });
  });

  it("a worker's node label is its real per-replica hostname, split out of the combined workerId, with its actuator port as the sub-label", () => {
    // Real shape from WorkerApplication#workerId: InetAddress hostname (a Docker container id in
    // practice) + "-" + an 8-hex-char random suffix disambiguating replicas.
    const w = worker({ workerId: "07cdfd745cfd-1c493827" });
    const graph = buildGraph([], new Map(), [w]);

    const node = graph.nodes.find((n) => n.id === "worker:07cdfd745cfd-1c493827")!;
    expect(node.label).toBe("07cdfd745cfd");
    expect(node.subLabel).toBe(":8081");
    expect(node.fullWorkerId).toBe("07cdfd745cfd-1c493827");
  });

  it("a worker id that doesn't match the expected hostname-suffix shape falls back to showing it whole, rather than mangling it", () => {
    const w = worker({ workerId: "not-the-expected-shape" });
    const graph = buildGraph([], new Map(), [w]);

    const node = graph.nodes.find((n) => n.id === "worker:not-the-expected-shape")!;
    expect(node.label).toBe("not-the-expected-shape");
  });

  it("the platform singleton nodes (hub, database, webui) each carry their real docker-compose hostname:port as a sub-label", () => {
    const graph = buildGraph([], new Map());

    expect(graph.nodes.find((n) => n.id === "hub")!.subLabel).toBe("central-server:8080");
    expect(graph.nodes.find((n) => n.id === "database")!.subLabel).toBe("postgres:5432");
    expect(graph.nodes.find((n) => n.id === "webui")!.subLabel).toBe("webui:8080");
  });

  it("a BUSY worker scanning a target that's in this graph gets a distinct 'scanning' link straight to it", () => {
    const t = target({ id: "t1" });
    const w = worker({ workerId: "w1", status: "BUSY", targetId: "t1", targetHostname: "example.com" });
    const graph = buildGraph([t], new Map([["t1", { sample: [], total: 0 }]]), [w]);

    expect(graph.links).toContainEqual({ source: "worker:w1", target: "target:t1", kind: "scanning" });
  });

  it("a BUSY worker scanning another organization's target (not in this graph) gets no scanning link", () => {
    // Matches WorkerPanel's own handling of this exact case: targetHostname/targetId present on
    // the wire but pointing at a target this org's graph has no node for.
    const w = worker({ workerId: "w1", status: "BUSY", targetId: "someone-elses-target", targetHostname: null });
    const graph = buildGraph([], new Map(), [w]);

    expect(graph.links.some((l) => l.kind === "scanning")).toBe(false);
  });

  it("an IDLE or OFFLINE worker never gets a scanning link even if it has a stale targetId", () => {
    const t = target({ id: "t1" });
    const idle = worker({ workerId: "w1", status: "IDLE", targetId: "t1" });
    const graph = buildGraph([t], new Map([["t1", { sample: [], total: 0 }]]), [idle]);

    expect(graph.links.some((l) => l.kind === "scanning")).toBe(false);
  });

  it("a Tier 2 worker whose currentHost is a rendered subdomain gets its scanning link pointed at that subdomain, not the target", () => {
    const t = target({ id: "t1", hostname: "example.com" });
    const subs = [sub("s1", "api.example.com"), sub("s2", "www.example.com")];
    const w = worker({ workerId: "w1", status: "BUSY", targetId: "t1", currentHost: "api.example.com" });
    const graph = buildGraph([t], new Map([["t1", { sample: subs, total: 2 }]]), [w]);

    expect(graph.links).toContainEqual({ source: "worker:w1", target: "sub:t1:s1", kind: "scanning" });
    expect(graph.links.some((l) => l.target === "target:t1" && l.kind === "scanning")).toBe(false);
  });

  it("a Tier 2 worker whose currentHost is the target's own apex hostname still points at the target node", () => {
    const t = target({ id: "t1", hostname: "example.com" });
    const w = worker({ workerId: "w1", status: "BUSY", targetId: "t1", currentHost: "example.com" });
    const graph = buildGraph([t], new Map([["t1", { sample: [], total: 0 }]]), [w]);

    expect(graph.links).toContainEqual({ source: "worker:w1", target: "target:t1", kind: "scanning" });
  });

  it("a currentHost outside the capped/rendered subdomain sample falls back to the target node, not a nonexistent node", () => {
    const t = target({ id: "t1", hostname: "example.com" });
    const subs = [sub("s1", "api.example.com")];
    const w = worker({ workerId: "w1", status: "BUSY", targetId: "t1", currentHost: "hidden-beyond-the-cap.example.com" });
    const graph = buildGraph([t], new Map([["t1", { sample: subs, total: 50 }]]), [w]);

    expect(graph.links).toContainEqual({ source: "worker:w1", target: "target:t1", kind: "scanning" });
  });

  it("a Tier 1 fanout worker with no currentHost keeps pointing at the target node, same as before", () => {
    const t = target({ id: "t1" });
    const w = worker({ workerId: "w1", status: "BUSY", targetId: "t1", currentHost: null });
    const graph = buildGraph([t], new Map([["t1", { sample: [], total: 0 }]]), [w]);

    expect(graph.links).toContainEqual({ source: "worker:w1", target: "target:t1", kind: "scanning" });
  });
});

describe("layoutGraph", () => {
  const WIDTH = 1200;
  const HEIGHT = 720;
  const DIAGONAL = Math.hypot(WIDTH, HEIGHT);

  it("keeps each target-type cluster's own node - and its full subdomain halo - well clear of the platform hub", () => {
    // A bug report found a WATCHLIST target's cluster visually sitting on top of the platform
    // cluster (central-server/postgres/webui/workers). Root cause: the old cluster centers put
    // WATCHLIST and platform on almost the same y-band (0.85h vs 0.78h, only 0.07*height apart),
    // relying entirely on a (large-looking, but not actually sufficient) x-axis gap to keep them
    // apart. A target's own subdomain nodes fan out from it under mutual repulsion - the more of
    // them, the further the whole halo can spread along a shared band - so centroid-to-centroid
    // distance alone doesn't catch this: two cluster centers can be far apart while their actual
    // rendered extents still collide. This checks every node belonging to each cluster (not just
    // its center) never comes within a "these are clearly the same cluster" distance of the hub.
    const types: TargetType[] = ["OWN", "COMPETITOR", "WATCHLIST"];
    const targets = types.map((t, i) => target({ id: `t-${t}`, targetType: t, hostname: `${i}.example.com` }));
    // A wide subdomain fan-out per target - the exact condition (many nodes, high mutual
    // repulsion) that let a cluster spread far enough to bridge a shared-band gap in the wild.
    const subdomainsByTarget = new Map(
      targets.map((t) => [
        t.id,
        {
          sample: Array.from({ length: SUBDOMAINS_PER_TARGET_CAP }, (_, i) => sub(`${t.id}-s${i}`, `h${i}.${t.hostname}`)),
          total: SUBDOMAINS_PER_TARGET_CAP,
        },
      ]),
    );
    const workers = [worker({ workerId: "w1" }), worker({ workerId: "w2" }), worker({ workerId: "w3" })];
    const graph = buildGraph(targets, subdomainsByTarget, workers);
    const laidOut = layoutGraph(graph, WIDTH, HEIGHT);

    const hub = laidOut.nodes.find((n) => n.id === "hub")!;
    // 12% of the canvas diagonal - comfortably inside "two clearly distinct clusters", loose
    // enough to tolerate simulation noise, but well short of what the old (buggy) coordinates
    // actually produced for the WATCHLIST cluster's closest members.
    const MIN_DISTANCE_FROM_HUB = DIAGONAL * 0.12;

    for (const type of types) {
      const clusterNodes = laidOut.nodes.filter(
        (n): n is GraphNode & { x: number; y: number } =>
          n.targetType === type && n.x != null && n.y != null,
      );
      expect(clusterNodes.length).toBeGreaterThan(0);
      for (const n of clusterNodes) {
        const dist = Math.hypot(n.x - hub.x!, n.y - hub.y!);
        expect(
          dist,
          `a ${type} node (${n.id}) is only ${dist.toFixed(0)}px from the platform hub`,
        ).toBeGreaterThan(MIN_DISTANCE_FROM_HUB);
      }
    }
  });

  it("populates x/y on every node, including the hub", () => {
    const graph = buildGraph([], new Map());
    const laidOut = layoutGraph(graph, WIDTH, HEIGHT);

    const hub = laidOut.nodes.find((n) => n.id === "hub")!;
    expect(hub.x).not.toBeNull();
    expect(hub.y).not.toBeNull();
  });
});

describe("colorForTargetType", () => {
  it("returns a distinct color per target type", () => {
    const own = colorForTargetType("OWN");
    const competitor = colorForTargetType("COMPETITOR");
    const watchlist = colorForTargetType("WATCHLIST");
    expect(new Set([own, competitor, watchlist]).size).toBe(3);
  });

  it("falls back to a neutral color when no type is given (the hub/platform nodes)", () => {
    expect(colorForTargetType(undefined)).toBe("#7a8aa0");
  });
});

describe("colorForNode", () => {
  it("platform nodes (hub, database, webui) all share the same distinct violet, never a target-type color", () => {
    const hubColor = colorForNode({ id: "hub", kind: "hub", label: "x", radius: 20 });
    const dbColor = colorForNode({ id: "database", kind: "database", label: "x", radius: 10 });
    const webuiColor = colorForNode({ id: "webui", kind: "webui", label: "x", radius: 9 });
    expect(hubColor).toBe(dbColor);
    expect(dbColor).toBe(webuiColor);
    expect(["#00f0ff", "#ff2e97", "#ffb800"]).not.toContain(hubColor);
  });

  it("a worker's color reflects its live status, not any target type", () => {
    const busy = colorForNode({ id: "worker:w1", kind: "worker", label: "w1", radius: 8, workerStatus: "BUSY" });
    const idle = colorForNode({ id: "worker:w1", kind: "worker", label: "w1", radius: 8, workerStatus: "IDLE" });
    expect(busy).not.toBe(idle);
  });

  it("a target/subdomain node's color still follows target type, unaffected by the platform palette", () => {
    expect(colorForNode({ id: "target:t1", kind: "target", label: "x", radius: 10, targetType: "OWN" })).toBe("#00f0ff");
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

  it("platform nodes (hub, database, webui, worker) have no href - nothing to navigate to", () => {
    expect(hrefForNode({ id: "hub", kind: "hub", label: "CENTRAL-SERVER", radius: 20 })).toBeUndefined();
    expect(hrefForNode({ id: "database", kind: "database", label: "POSTGRES", radius: 10 })).toBeUndefined();
    expect(hrefForNode({ id: "webui", kind: "webui", label: "WEBUI", radius: 9 })).toBeUndefined();
    expect(hrefForNode({ id: "worker:w1", kind: "worker", label: "w1", radius: 8 })).toBeUndefined();
  });
});

function subdomainNode(id: string, x: number, y: number, label = id): GraphNode {
  return { id, kind: "subdomain", label, radius: 5, x, y };
}

describe("selectNonOverlappingSubdomainLabels", () => {
  it("keeps a single subdomain's label", () => {
    const visible = selectNonOverlappingSubdomainLabels([subdomainNode("a", 0, 0)]);
    expect(visible.has("a")).toBe(true);
  });

  it("keeps two subdomains' labels when they're far enough apart not to overlap", () => {
    const visible = selectNonOverlappingSubdomainLabels([subdomainNode("a", 0, 0), subdomainNode("b", 500, 500)]);
    expect(visible.has("a")).toBe(true);
    expect(visible.has("b")).toBe(true);
  });

  it("drops the later node's label when two subdomains sit close enough for their labels to overlap", () => {
    // Same label text, same y, 3px apart on x - their label rectangles are guaranteed to
    // overlap regardless of the exact width estimate used.
    const visible = selectNonOverlappingSubdomainLabels([
      subdomainNode("a", 0, 0, "example.example.co.uk"),
      subdomainNode("b", 3, 0, "example.example.co.uk"),
    ]);
    expect(visible.has("a")).toBe(true);
    expect(visible.has("b")).toBe(false);
  });

  it("ignores non-subdomain nodes and nodes with no laid-out position", () => {
    const visible = selectNonOverlappingSubdomainLabels([
      { id: "target:t1", kind: "target", label: "example.com", radius: 12, x: 0, y: 0 },
      { id: "sub:t1:no-pos", kind: "subdomain", label: "unpositioned.example.com", radius: 5 },
    ]);
    expect(visible.size).toBe(0);
  });
});
