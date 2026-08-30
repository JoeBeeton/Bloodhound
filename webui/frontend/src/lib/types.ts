export interface UserSummary {
  id: string;
  email: string;
  displayName: string;
  role: string;
  organizationId: string;
}

export interface AuthState {
  accessToken: string;
  expiresIn: number;
  user: UserSummary;
}

export type TargetType = "OWN" | "COMPETITOR" | "WATCHLIST";

export type Grade = "A" | "B" | "C" | "D" | "F";

/** One target_authorizations attestation row - GET /api/v1/targets/{id}/authorization's history. */
export interface AuthorizationEntry {
  id: string;
  authorizedByUserId: string;
  authorizedAt: string;
  attestationText: string;
  revokedAt: string | null;
}

export interface AuthorizationStatusResponse {
  authorizationStatus: "UNAUTHORIZED" | "AUTHORIZED";
  history: AuthorizationEntry[];
}

export interface Target {
  id: string;
  hostname: string;
  targetType: TargetType;
  authorizationStatus: "UNAUTHORIZED" | "AUTHORIZED";
  scanCadenceSeconds: number;
  nextScanAt: string;
  isActive: boolean;
  createdAt: string;
  /** Absent until a target's first scan has completed. */
  overallScore: number | null;
  grade: Grade | null;
  /**
   * "Fair comparison" score excluding findings only a Tier 2 deep scan could have produced
   * (Tier 2 only ever runs against authorized - in practice, your own - targets). Absent
   * until a scan completes, or on snapshots taken before this was added.
   */
  tier1OverallScore: number | null;
  tier1Grade: Grade | null;
  /** Absent until this target has had its first scan (CT_CHECK/CVE_CORRELATION don't count). */
  lastScanAt: string | null;
  /** Null alongside lastScanAt when there's no scan yet; true for a Tier 2 deep scan, false for a regular Tier 1 scan. */
  lastScanWasDeep: boolean | null;
  /** Free-text context an analyst leaves on a target (which environment, who owns it, why it's tracked) - absent for most existing targets. */
  notes: string | null;
}

/** Mirrors ScoringEngine.CATEGORY_WEIGHTS on the backend exactly - WEB_APP (ZAP/Nuclei
 * findings) carries real weight (15%) same as the other six, it's just Tier2-only (see
 * Target.tier1OverallScore's own doc comment) so it only ever shows up for authorized/owned
 * targets. Confirmed live: a real snapshot's categoryScores includes a WEB_APP key. */
export const SCORE_CATEGORIES = ["EXPOSURE", "TLS", "DNS", "NETWORK", "HEADERS", "SUBDOMAIN_HYGIENE", "WEB_APP"] as const;
export type ScoreCategory = (typeof SCORE_CATEGORIES)[number];

/**
 * Every category a real finding can carry - SCORE_CATEGORIES above (the 7 that
 * factor into ScoringEngine's weight table) plus the categories that deliberately
 * don't (WHOIS, BREACH, BRAND, COMPOUND - see ScoringEngineTest's
 * "unmapped category" precedent). Used for findings-filter UI, not scoring.
 */
export const FINDING_CATEGORIES = [
  "EXPOSURE",
  "TLS",
  "DNS",
  "NETWORK",
  "HEADERS",
  "SUBDOMAIN_HYGIENE",
  "WHOIS",
  "BREACH",
  "WEB_APP",
  "BRAND",
  "COMPOUND",
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export interface ScoreSnapshot {
  id: string;
  scanRunId: string;
  computedAt: string;
  overallScore: number;
  grade: Grade;
  categoryScores: Record<ScoreCategory, number>;
  findingCounts: Record<Severity, number>;
  /** Same "fair comparison" caveat as Target.tier1OverallScore - null on pre-fix snapshots. */
  tier1OverallScore: number | null;
  tier1Grade: Grade | null;
  tier1CategoryScores: Record<ScoreCategory, number> | null;
}

export type ScanRunStatus = "RUNNING" | "COMPLETE" | "PARTIAL_FAILURE";

export interface ScanJobAttempt {
  attemptNumber: number;
  claimedBy: string;
  startedAt: string;
  endedAt: string | null;
  outcome: "SUCCESS" | "FAILED" | "TIMED_OUT_REAPED" | null;
  errorDetail: string | null;
  /** Captured worker log output for this attempt, newline-joined - null when nothing was captured (e.g. a TIMED_OUT_REAPED attempt the worker never got to report on). */
  logOutput: string | null;
}

export interface ScanJobStatus {
  id: string;
  moduleType: string;
  status: string;
  attemptCount: number;
  maxAttempts: number;
  errorDetail: string | null;
  attempts: ScanJobAttempt[];
  /** The specific host this job scans - only set for Tier 2 (one-job-per-host) jobs. */
  host: string | null;
}

export interface ScanRunDetail {
  id: string;
  targetId: string;
  targetHostname: string;
  triggeredBy: string;
  startedAt: string;
  completedAt: string | null;
  status: ScanRunStatus;
  jobs: ScanJobStatus[];
}

export interface ActiveScanModule {
  moduleType: string;
  status: string;
  /** The specific host this job scans - only set for Tier 2 (one-job-per-host) jobs. */
  host: string | null;
}

export interface ActiveScan {
  id: string;
  targetId: string;
  targetHostname: string;
  triggeredBy: string;
  startedAt: string;
  completedJobs: number;
  totalJobs: number;
  /** Null when no still-incomplete module has enough historical data to estimate against - see ScanEtaEstimator. */
  etaSeconds: number | null;
  modules: ActiveScanModule[];
}

/** A past scan (any terminal status, or still RUNNING) - what backs the "Recent scans" history
 * list on the scans page, so a since-failed scan stays findable/diagnosable after it drops out
 * of the active list. */
export interface RecentScan {
  id: string;
  targetId: string;
  targetHostname: string;
  triggeredBy: string;
  status: string;
  startedAt: string;
  completedAt: string | null;
}

export interface WorkerStatus {
  workerId: string;
  status: "IDLE" | "BUSY" | "OFFLINE";
  lastHeartbeatAt: string;
  targetId: string | null;
  /** Null unless BUSY on a job belonging to the caller's own org - see WorkersController. */
  targetHostname: string | null;
  moduleType: string | null;
  /** The specific host being scanned right now (Tier 2 jobs only) - null for Tier 1, or if BUSY on another org's job. */
  currentHost: string | null;
}

export interface Subdomain {
  id: string;
  hostname: string;
  firstSeenAt: string;
  lastSeenAt: string;
  source: string;
  isActive: boolean;
  currentIpAddresses: string[];
}

export interface Technology {
  name: string;
  category: string;
  version: string | null;
}

export interface FingerprintEntry {
  hostname: string;
  technologies: Technology[];
  hostingProvider: string | null;
  hostingAsn: string | null;
  hostingAsnOrg: string | null;
  /** Distinct external origins this hostname's <script>/<iframe> tags actually load from (analytics, tag managers, embed widgets) - not itself a severity signal, just supply-chain visibility. */
  thirdPartyOrigins: string[];
  capturedAt: string;
}

/** A registered (never an unregistered) lookalike domain flagged by typosquat monitoring — GET /targets/:id/typosquats already filters to is_registered=true server-side. */
export interface TyposquatCandidate {
  id: string;
  candidateDomain: string;
  permutationType: string;
  firstSeenAt: string;
  lastCheckedAt: string;
  resolvedIp: string | null;
  registrationDate: string | null;
  hasScreenshot: boolean;
  visualSimilarityPercent: number | null;
}

/** GET /api/v1/targets/{id}/typosquats' response shape. */
export interface TyposquatListResponse {
  realDomainHasScreenshot: boolean;
  candidates: TyposquatCandidate[];
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

/**
 * How much the target's score would change if this one finding were remediated,
 * computed by re-running the real scoring engine with it excluded (not a shortcut
 * formula, so it correctly accounts for the diminishing-returns discount shifting
 * across the findings that remain). affectsScore is false - and every other field
 * null - for a finding in a category outside the fixed scoring weight table (WHOIS,
 * WEB_APP): those can never move the score, so there's nothing to report.
 * scoreImpact itself is null when the endpoint didn't compute one at all (e.g. a
 * historical run-diff view, or a status=RESOLVED findings query).
 */
export interface ScoreImpact {
  affectsScore: boolean;
  category: string;
  categoryScoreBefore: number | null;
  categoryScoreAfter: number | null;
  overallScoreDelta: number | null;
}

export interface Finding {
  id: string;
  /** Stable, human-friendly per-target label ("bh-jaja.co.uk-1") - easier to reference than the raw id. */
  displayId: string;
  targetId: string;
  moduleType: string;
  ruleId: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  affectedAsset: string;
  firstDetectedScanRunId: string;
  status: "OPEN" | "RESOLVED" | "ACCEPTED_RISK";
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  /** The completed_at of the scan run that first detected this finding. Null for the run-diff view's historical reconstruction. */
  firstSeenAt: string | null;
  /** Bumped every time a later scan reproduces this same finding - when it was last observed still open. */
  lastSeenAt: string;
  /** From rules_catalog, falling back to evidence.solution for ZAP_ALERT_* rule_ids which have no catalog row. Null if neither is available. */
  remediationAdvice: string | null;
  scoreImpact: ScoreImpact | null;
}

/** One target's score history, as returned by /api/v1/compare - a single series in the multi-line compare chart. */
export interface CompareSeries {
  targetId: string;
  hostname: string;
  targetType: TargetType;
  history: ScoreSnapshot[];
}

export interface SeverityChange {
  before: Finding;
  after: Finding;
}

/** Run-over-run findings diff. baselineRunId/baselineComputedAt are null when compareRun is a target's first-ever completed scan. */
export interface FindingDiffResponse {
  targetId: string;
  baselineRunId: string | null;
  baselineComputedAt: string | null;
  compareRunId: string;
  compareComputedAt: string;
  newFindings: Finding[];
  resolvedFindings: Finding[];
  unchangedFindings: Finding[];
  changedSeverity: SeverityChange[];
}

/** A finding paired with the hostname of the target it belongs to - the org-wide /api/v1/findings shape. */
export interface OrgFinding {
  id: string;
  displayId: string;
  targetId: string;
  targetHostname: string;
  moduleType: string;
  ruleId: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  affectedAsset: string;
  status: "OPEN" | "RESOLVED" | "ACCEPTED_RISK";
  resolvedAt: string | null;
  createdAt: string;
  firstSeenAt: string | null;
  lastSeenAt: string;
  remediationAdvice: string | null;
  scoreImpact: ScoreImpact | null;
}

export interface RecentActivity {
  id: string;
  targetId: string;
  targetHostname: string;
  status: ScanRunStatus;
  startedAt: string;
  completedAt: string | null;
}

export interface DashboardStats {
  totalTargets: number;
  ownCount: number;
  competitorCount: number;
  watchlistCount: number;
  openCriticalCount: number;
  openHighCount: number;
}

/** The org-overview aggregate GET /api/v1/dashboard returns in one round trip. */
export interface DashboardSummary {
  ownTargets: Target[];
  topFindings: OrgFinding[];
  recentFindings: OrgFinding[];
  recentActivity: RecentActivity[];
  stats: DashboardStats;
}

/**
 * The GET/PATCH /api/v1/orgs/{orgId}/users shape - a separate type from the
 * auth UserSummary above (which is what login/refresh return for the
 * *current* user and doesn't carry status): this is the admin user-list
 * shape, one row per org member.
 */
export interface AdminUser {
  id: string;
  email: string;
  displayName: string;
  role: string;
  status: string;
  organizationId: string;
  mcpEnabled: boolean;
  /** "LOCAL" (password-based) or "SAML" (SSO - no local password to reset). */
  identitySource: string;
  /** Null if this user has never successfully logged in. */
  lastLoginAt: string | null;
}

export type UserRole = "ADMIN" | "ANALYST" | "VIEWER";
export type UserStatus = "ACTIVE" | "DISABLED";

/** POST /api/v1/orgs/{orgId}/users response - the temporary password is shown exactly once. */
export interface CreateUserResponse {
  user: AdminUser;
  temporaryPassword: string;
}

/** GET /api/v1/rules-catalog - every check Bloodhound runs, doubling as in-product documentation. */
export interface RulesCatalogEntry {
  ruleId: string;
  category: string;
  defaultSeverity: Severity;
  title: string;
  description: string;
  remediationAdvice: string;
  weight: number;
  enabled: boolean;
}

/** GET /api/v1/admin/security-status (ADMIN only) - deployment-wide misconfigurations that would otherwise only ever show up in server logs. */
export interface SecurityStatus {
  jwtSigningKeyIsPlaceholder: boolean;
  workerApiKeyIsPlaceholder: boolean;
}
