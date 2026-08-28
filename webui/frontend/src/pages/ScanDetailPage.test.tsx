import { describe, expect, it } from "vitest";
import { groupJobsByModule } from "./ScanDetailPage";
import type { ScanJobStatus } from "../lib/types";

function job(moduleType: string, host: string | null = null, status = "COMPLETE"): ScanJobStatus {
  return {
    id: `${moduleType}-${host ?? "root"}`,
    moduleType,
    status,
    attemptCount: 1,
    maxAttempts: 3,
    errorDetail: null,
    attempts: [],
    host,
  };
}

describe("groupJobsByModule", () => {
  it("keeps a Tier 1 scan's one-job-per-module shape as singleton groups", () => {
    const groups = groupJobsByModule([job("DNS_POSTURE"), job("HTTP_HEADERS"), job("TLS_ANALYSIS")]);
    expect(groups).toHaveLength(3);
    expect(groups.every((g) => g.jobs.length === 1)).toBe(true);
  });

  it("groups a Tier 2 scan's per-host jobs under one entry per module type", () => {
    const groups = groupJobsByModule([
      job("PORT_SCAN_DEEP", "a.example.com"),
      job("PORT_SCAN_DEEP", "b.example.com"),
      job("ZAP_ACTIVE_SCAN", "a.example.com"),
    ]);
    expect(groups).toHaveLength(2);
    const portScan = groups.find((g) => g.moduleType === "PORT_SCAN_DEEP");
    expect(portScan?.jobs).toHaveLength(2);
    const zap = groups.find((g) => g.moduleType === "ZAP_ACTIVE_SCAN");
    expect(zap?.jobs).toHaveLength(1);
  });

  it("preserves each module's first-seen order across groups", () => {
    const groups = groupJobsByModule([job("WHOIS"), job("DNS_POSTURE"), job("WHOIS")]);
    expect(groups.map((g) => g.moduleType)).toEqual(["WHOIS", "DNS_POSTURE"]);
  });
});
