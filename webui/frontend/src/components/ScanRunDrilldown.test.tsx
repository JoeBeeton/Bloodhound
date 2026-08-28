import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { ScanRunDrilldown } from "./ScanRunDrilldown";
import type { ScanJobStatus, ScanRunDetail } from "../lib/types";

function job(moduleType: string, host: string | null, status: string, overrides: Partial<ScanJobStatus> = {}): ScanJobStatus {
  return {
    id: `${moduleType}-${host ?? "root"}`,
    moduleType,
    status,
    attemptCount: status === "FAILED" ? 3 : 1,
    maxAttempts: 3,
    errorDetail: null,
    attempts: [],
    host,
    ...overrides,
  };
}

// Mirrors a real Tier 2 deep scan run (verified live: jaja.co.uk's 72ede55a run -
// 43 COMPLETE, 5 FAILED, all 5 failures in ZAP_ACTIVE_SCAN out of its 16 hosts).
function deepScanRun(): ScanRunDetail {
  const hosts = Array.from({ length: 16 }, (_, i) => `host${i}.example.com`);
  return {
    id: "run-1",
    targetId: "target-1",
    targetHostname: "example.com",
    triggeredBy: "MANUAL",
    startedAt: "2026-08-28T00:00:00Z",
    completedAt: "2026-08-28T00:30:00Z",
    status: "PARTIAL_FAILURE",
    jobs: [
      ...hosts.map((h) => job("PORT_SCAN_DEEP", h, "COMPLETE")),
      ...hosts.slice(0, 11).map((h) => job("ZAP_ACTIVE_SCAN", h, "COMPLETE")),
      ...hosts.slice(11).map((h) => job("ZAP_ACTIVE_SCAN", h, "FAILED", { errorDetail: "connection timed out" })),
      ...hosts.map((h) => job("NUCLEI_SCAN", h, "COMPLETE")),
    ],
  };
}

function renderDrilldown(run: ScanRunDetail) {
  return render(
    <MemoryRouter>
      <ScanRunDrilldown run={run} />
    </MemoryRouter>,
  );
}

describe("ScanRunDrilldown", () => {
  it("renders nothing when no job failed", () => {
    const run = deepScanRun();
    run.jobs = run.jobs.map((j) => (j.status === "FAILED" ? { ...j, status: "COMPLETE", errorDetail: null } : j));
    const { container } = renderDrilldown(run);
    expect(container).toBeEmptyDOMElement();
  });

  it("counts failed MODULES, not failed jobs, in the collapsed toggle", () => {
    renderDrilldown(deepScanRun());
    // Only ZAP_ACTIVE_SCAN failed (5 of its 16 host-jobs) - one module, not five.
    expect(screen.getByText("Why? (1 module failed) ▾")).toBeInTheDocument();
  });

  it("groups a 48-job Tier 2 run into 3 rows (one per module), not 48", async () => {
    const user = userEvent.setup();
    renderDrilldown(deepScanRun());
    await user.click(screen.getByText(/Why\?/));

    expect(screen.getByText("PORT_SCAN_DEEP")).toBeInTheDocument();
    expect(screen.getByText("NUCLEI_SCAN")).toBeInTheDocument();
    expect(screen.getByText(/ZAP_ACTIVE_SCAN/)).toBeInTheDocument();
    // Three modules, each with a "(16 hosts)" host count - one row per module, not one per
    // of the 48 underlying jobs.
    expect(screen.getAllByText("(16 hosts)")).toHaveLength(3);
    expect(screen.getByText("5/16 FAILED")).toBeInTheDocument();
    expect(screen.getByText(/connection timed out/)).toBeInTheDocument();
  });
});
