import { describe, expect, it } from "vitest";
import { scanHasFailure } from "./ScansPage";
import type { ActiveScan } from "../lib/types";

function scan(modules: Array<{ moduleType: string; status: string; host?: string | null }>): ActiveScan {
  return {
    id: "scan-1",
    targetId: "target-1",
    targetHostname: "example.com",
    triggeredBy: "manual",
    startedAt: new Date().toISOString(),
    completedJobs: 0,
    totalJobs: modules.length,
    etaSeconds: 30,
    modules: modules.map((m) => ({ moduleType: m.moduleType, status: m.status, host: m.host ?? null })),
  };
}

describe("scanHasFailure", () => {
  it("is false when every module is still running or complete", () => {
    expect(
      scanHasFailure(
        scan([
          { moduleType: "DNS", status: "COMPLETE" },
          { moduleType: "TLS", status: "RUNNING" },
        ]),
      ),
    ).toBe(false);
  });

  it("is true when any module has failed, regardless of the others' status", () => {
    expect(
      scanHasFailure(
        scan([
          { moduleType: "DNS", status: "COMPLETE" },
          { moduleType: "TLS", status: "FAILED" },
          { moduleType: "HEADERS", status: "RUNNING" },
        ]),
      ),
    ).toBe(true);
  });

  it("is false for a scan with no modules yet", () => {
    expect(scanHasFailure(scan([]))).toBe(false);
  });
});
