import { describe, expect, it } from "vitest";
import { statusDisplay } from "./AdminScimPage";

interface ScimTokenSummary {
  id: string;
  label: string;
  createdAt: string;
  revokedAt: string | null;
  expiresAt: string | null;
  expired: boolean;
}

function token(overrides: Partial<ScimTokenSummary> = {}): ScimTokenSummary {
  return {
    id: "t1",
    label: "Okta",
    createdAt: "2026-01-01T00:00:00Z",
    revokedAt: null,
    expiresAt: null,
    expired: false,
    ...overrides,
  };
}

const NOW = new Date("2026-05-01T00:00:00Z").getTime();

describe("AdminScimPage statusDisplay", () => {
  it("shows 'Active · never expires' for the deliberate default (no expiresAt at all)", () => {
    // Unlike ApiKeysPage, this is the expected default for a continuous directory-sync
    // credential, not a fallback for missing data - see V44__scim_token_expiry.sql.
    expect(statusDisplay(token(), NOW)).toEqual({ label: "Active · never expires", className: "text-neon-cyan" });
  });

  it("shows a plain 'Active' when an explicit expiry is comfortably in the future", () => {
    expect(statusDisplay(token({ expiresAt: "2026-12-01T00:00:00Z" }), NOW)).toEqual({
      label: "Active",
      className: "text-neon-cyan",
    });
  });

  it("warns in amber once an explicit expiry is within 14 days", () => {
    const status = statusDisplay(token({ expiresAt: "2026-05-10T00:00:00Z" }), NOW);
    expect(status.label).toBe("Active · 9d left");
    expect(status.className).toBe("text-neon-amber");
  });

  it("shows 'Revoked' regardless of expiry (including a token that never expires)", () => {
    expect(statusDisplay(token({ revokedAt: "2026-04-15T00:00:00Z" }), NOW)).toEqual({
      label: "Revoked",
      className: "text-slate-500",
    });
  });

  it("shows 'Expired' rather than a negative day count once past an explicit expiry", () => {
    expect(statusDisplay(token({ expired: true, expiresAt: "2026-04-01T00:00:00Z" }), NOW)).toEqual({
      label: "Expired",
      className: "text-neon-amber",
    });
  });
});
