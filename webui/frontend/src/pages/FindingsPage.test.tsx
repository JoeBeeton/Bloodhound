import { describe, expect, it } from "vitest";
import { orgFindingsFilterParams, parseStatusParam } from "./FindingsPage";

describe("orgFindingsFilterParams / parseStatusParam", () => {
  // A live UX bug found after FindingsFilterBar gained its third "Dismissed" toggle: both
  // functions here only ever recognized the literal string "RESOLVED" (copy-pasted into this
  // org-wide page from the target-scoped one, which had the identical bug), so clicking Dismissed
  // rendered as pressed/active but the status param was silently dropped, leaving the page
  // showing Open findings the whole time. These are the exact regression case.
  it("forwards DISMISSED, not just RESOLVED, in the outgoing query params", () => {
    const params = orgFindingsFilterParams({ severities: [], categories: [], status: "DISMISSED" });
    expect(params.get("status")).toBe("DISMISSED");
  });

  it("forwards RESOLVED too - the case that was already working", () => {
    const params = orgFindingsFilterParams({ severities: [], categories: [], status: "RESOLVED" });
    expect(params.get("status")).toBe("RESOLVED");
  });

  it("omits the status param entirely for OPEN - the server's own default", () => {
    const params = orgFindingsFilterParams({ severities: [], categories: [], status: "OPEN" });
    expect(params.has("status")).toBe(false);
  });

  it("reads DISMISSED back from a URL param, not just RESOLVED", () => {
    expect(parseStatusParam("DISMISSED")).toBe("DISMISSED");
    expect(parseStatusParam("RESOLVED")).toBe("RESOLVED");
  });

  it("defaults anything unrecognized (absent, stale, hand-edited) back to OPEN", () => {
    expect(parseStatusParam(null)).toBe("OPEN");
    expect(parseStatusParam("garbage")).toBe("OPEN");
  });
});
