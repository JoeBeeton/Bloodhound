# TODO

Backlog of concrete, not-yet-scheduled work. Not a roadmap - just things worth doing that haven't been picked up yet.

- ~~WordPress fingerprinting, JS library fingerprinting, other CMS
  fingerprinting~~ **Done.** Turned out WordPress core detection + version +
  CVE-slug mapping already existed when this item was written (an
  assumption I should have verified before adding it, not just checking
  code by grep) - the real remaining gaps were plugin/theme version
  disclosure (now detected via WordPress's own `?ver=` asset-enqueue
  convention, reported as separate `Technology` entries per plugin/theme),
  jQuery/Bootstrap version extraction (were name-only), Magento detection
  (was entirely missing), and Drupal major-version extraction. Checked
  Wappalyzer as the obvious OSS fingerprint-database option first - its
  data is GPLv3 (both `enthec/webappanalyzer` and `HTTPArchive/wappalyzer`,
  verified against each repo's actual `LICENSE` file), same class of
  conflict as nmap, so every new signature is hand-written against publicly
  observable facts instead. `ProductSlugMapper` gained jQuery/Bootstrap/
  Drupal entries; per-plugin CVE-slug mapping for WordPress plugins was
  deliberately left out (thousands of slugs, doesn't scale the way mapping
  a handful of platforms does) - worth its own properly-scoped item if
  picked up later.

- ~~Cloud storage bucket misconfiguration checks~~ **Done.** CNAME-based
  discovery (a subdomain aliased directly to a bucket - the "passive DNS
  correlation" the original design called for), scoped to AWS S3 and Google
  Cloud Storage - deliberately **not** Azure Blob Storage: Azure's
  custom-domain mapping is account-level, not container-level, so the CNAME
  target alone never identifies which container to check, and guessing
  would cross into the brute-forcing this deliberately avoids. New rule
  `EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING` (Critical), wired through the same
  "computed live every run, re-confirmed or resolves" pattern
  `SUBDOMAIN_DANGLING_CNAME` already uses - same underlying CNAME data,
  different question (unclaimed vs. claimed-but-publicly-readable). See
  `CloudBucketDecisionLogic`/`CloudBucketChecker` (worker) and
  `SubdomainIngestionService` (central-server).

- **Wire up a real `BreachCorrelationSource`.** `NoOpBreachCorrelationSource`
  is the only implementation that ships - `BreachCorrelationModule` never
  even calls it when `HIBP_API_KEY` is unset (the common case). The
  extension point already exists; this is "finish what's started," not new
  architecture. Have I Been Pwned's domain-search API is the obvious
  candidate.

- **NS-delegation subdomain takeover detection.** Distinct from the existing
  CNAME-dangling check (`SUBDOMAIN_DANGLING_CNAME`): a subdomain delegated to
  a nameserver that's since been deprovisioned (e.g. a deleted Route53
  hosted zone) can be claimed by someone else entirely. Different attack
  vector, same severity class as the CNAME case, not currently covered by
  `DNS_NS_LAME_DELEGATION` (that's about broken answers, not claimable
  delegation).

- **Secret-pattern scanning inside already-exposed files.** The exposure
  checks already flag that `.env`/`.git/config`/AWS-credential files are
  *reachable* (`EXPOSURE_ENV_FILE`, `EXPOSURE_GIT_CONFIG`,
  `EXPOSURE_AWS_CREDENTIALS`); this would grep their actual contents for
  live-looking key patterns (regex-based, gitleaks-style), turning "a file
  is exposed" into "here's what's actually in it."

- **IPv6 exposure parity.** The port scanner and ASN lookup are IPv4-only
  right now (see `AsnDecisionLogic.reverseIpv4`). A target can have an
  equally-exposed IPv6 address that's never checked at all - exactly the
  kind of blind spot attackers look for precisely because it's
  under-monitored.

- **Document metadata leakage.** Author names, internal file paths, and
  software versions embedded in discovered PDFs/Office documents - classic
  OSINT technique, Tier 1-safe (passive fetch + metadata parse), but a new
  module family rather than an extension of an existing one.

- **Third-party script/tag-manager inventory.** Info-level signal: how many
  external origins does a page actually trust (analytics, tag managers,
  embedded widgets)? Each one is a supply-chain dependency the target may
  not be tracking itself.

- **Nuclei (ProjectDiscovery) as a Tier 2 module.** Template-based scanning
  for known CVEs/misconfigurations - a lot of overlap with what
  `CVE_CORRELATION` does passively, but nuclei actually confirms
  exploitability against the live target rather than inferring it from a
  detected version string, which is a real step up in signal quality for
  the findings it produces. License checked up front this time: MIT,
  confirmed against nuclei's own `LICENSE.md` - no repeat of the nmap
  situation. Belongs in Tier 2, not Tier 1: nuclei templates send real
  probes/payloads (the same category of intrusiveness as `ZAP_ACTIVE_SCAN`),
  so this needs the same `authorization_status = AUTHORIZED` gate as the
  existing Tier 2 modules, not a bare addition to the passive scan set.