/** Friendly display names for scan module_type values - no such mapping existed anywhere in
 * the frontend before this (module types were shown as their raw enum strings everywhere,
 * e.g. ScanDetailPage's job list) - this is the canonical one, reuse it rather than adding
 * a second. Falls back to the raw value for anything not listed, so a future module type
 * degrades gracefully instead of rendering blank. */
const MODULE_LABELS: Record<string, string> = {
  DNS_POSTURE: "DNS Posture",
  HTTP_HEADERS: "HTTP Headers",
  TLS_ANALYSIS: "TLS Analysis",
  SUBDOMAIN_ENUM: "Subdomain Enumeration",
  EXPOSURE_CHECKS: "Exposure Checks",
  PORT_SCAN_LIGHT: "Light Port Scan",
  WHOIS: "WHOIS / RDAP",
  TECH_FINGERPRINT: "Tech Fingerprinting",
  TYPOSQUAT_MONITOR: "Typosquat Monitor",
  CT_CHECK: "Certificate Transparency Check",
  PORT_SCAN_DEEP: "Deep Port Scan",
  ZAP_ACTIVE_SCAN: "Active Scan (OWASP ZAP)",
  CVE_CORRELATION: "CVE / KEV Correlation",
  BUCKET_BRUTE_FORCE: "Cloud Bucket Brute Force",
  // Pre-existing gaps, backfilled while adding the entry above - both already degraded
  // gracefully to their raw enum string rather than rendering blank, but there's no reason
  // for them to stay unmapped now that this file is already being touched.
  NUCLEI_SCAN: "Template Vulnerability Scan (Nuclei)",
  BREACH_CORRELATION: "Breach Correlation",
  DOCUMENT_METADATA: "Document Metadata",
};

export function moduleLabel(moduleType: string | null | undefined): string {
  if (!moduleType) return "";
  return MODULE_LABELS[moduleType] ?? moduleType;
}
