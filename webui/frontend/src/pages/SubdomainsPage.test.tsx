import { describe, expect, it } from "vitest";
import { byMostSevereFindingsFirst } from "./SubdomainsPage";
import type { Finding, Severity, Subdomain } from "../lib/types";

function subdomain(hostname: string): Subdomain {
  return {
    id: hostname,
    hostname,
    firstSeenAt: "2026-01-01T00:00:00Z",
    lastSeenAt: "2026-01-01T00:00:00Z",
    source: "crt.sh",
    isActive: true,
    currentIpAddresses: [],
  };
}

function finding(affectedAsset: string, severity: Severity): Finding {
  return {
    id: `${affectedAsset}-${severity}`,
    displayId: `bh-${affectedAsset}-1`,
    targetId: "target-1",
    moduleType: "tls",
    ruleId: "rule",
    severity,
    category: "TLS",
    title: "test finding",
    description: "",
    evidence: {},
    affectedAsset,
    firstDetectedScanRunId: "run-1",
    status: "OPEN",
    resolvedAt: null,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    firstSeenAt: "2026-01-01T00:00:00Z",
  } as Finding;
}

function byHostname(...findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = map.get(f.affectedAsset) ?? [];
    list.push(f);
    map.set(f.affectedAsset, list);
  }
  return map;
}

describe("byMostSevereFindingsFirst", () => {
  it("ranks a CRITICAL finding above a HIGH finding, regardless of input order", () => {
    const rows = [subdomain("low-risk.example.com"), subdomain("critical.example.com")];
    const findings = byHostname(finding("low-risk.example.com", "HIGH"), finding("critical.example.com", "CRITICAL"));
    const sorted = byMostSevereFindingsFirst(rows, findings);
    expect(sorted.map((s) => s.hostname)).toEqual(["critical.example.com", "low-risk.example.com"]);
  });

  it("breaks a severity tie by finding count", () => {
    const rows = [subdomain("one-high.example.com"), subdomain("three-high.example.com")];
    const findings = byHostname(
      finding("one-high.example.com", "HIGH"),
      finding("three-high.example.com", "HIGH"),
      finding("three-high.example.com", "HIGH"),
      finding("three-high.example.com", "HIGH"),
    );
    const sorted = byMostSevereFindingsFirst(rows, findings);
    expect(sorted.map((s) => s.hostname)).toEqual(["three-high.example.com", "one-high.example.com"]);
  });

  it("sinks a clean subdomain (no findings at all) to the bottom", () => {
    const rows = [subdomain("clean.example.com"), subdomain("info-only.example.com")];
    const findings = byHostname(finding("info-only.example.com", "INFO"));
    const sorted = byMostSevereFindingsFirst(rows, findings);
    expect(sorted.map((s) => s.hostname)).toEqual(["info-only.example.com", "clean.example.com"]);
  });

  it("does not mutate the input array", () => {
    const rows = [subdomain("b.example.com"), subdomain("a.example.com")];
    const original = [...rows];
    byMostSevereFindingsFirst(rows, byHostname(finding("a.example.com", "CRITICAL")));
    expect(rows).toEqual(original);
  });
});
