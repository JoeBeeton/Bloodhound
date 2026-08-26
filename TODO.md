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

- ~~Wire up a real `BreachCorrelationSource`~~ **Done.**
  `HibpBreachCorrelationSource` (`@Primary`) implements it against Have I
  Been Pwned's domain-search API; `BREACH_CORRELATION` is now in
  `ScanRunService.TIER1_MODULE_TYPES` so every scan enqueues it, and
  `HIBP_API_KEY` is wired through `docker-compose.yml`/`.env.example`
  (optional, unset by default - the module still costs nothing without a
  key, confirmed live: `{"enabled": false}`, zero HTTP calls). **One real
  limitation, not fully resolvable in code:** HIBP's domain-search endpoint
  only returns data for domains the operator has separately, manually
  verified ownership of in their own HIBP account (DNS TXT record, email
  approval, or their dashboard) - an unverified domain returns HTTP 403
  regardless of key validity, every time. Handled as "no data" rather than
  an error, so it never fails a scan, but it does mean this won't produce
  any findings until that manual, per-domain, account-level step happens -
  something only the operator can do, outside anything a scan can automate.
  Also unlike everything else fetch-related in this codebase, **not
  live-verified against a real subscription** - written strictly to HIBP's
  documented API contract (no key available to test against for real).
  Worth a genuine end-to-end check once a subscription + verified domain
  exist.

- ~~NS-delegation subdomain takeover detection~~ **Done.** New rule
  `SUBDOMAIN_NS_DELEGATION_TAKEOVER` (Critical). Reused
  `DnsZoneFetcher`'s exact "query the claimed nameserver directly for a SOA,
  see if it answers authoritatively" mechanic (already built for the
  apex-only `DNS_NS_LAME_DELEGATION` check) - what makes this one different
  and more severe isn't the query itself, it's checking specifically whether
  the lame nameserver belongs to a known cloud DNS provider (Route53, Azure
  DNS, Google Cloud DNS, DigitalOcean), which is what makes a lame answer
  attacker-*claimable* rather than just misconfigured. Wired into
  `SubdomainEnumModule` alongside the CNAME/bucket checks (new
  `SubdomainDnsResolver.resolveNameServers`), same
  "computed live every run, re-confirmed or resolves" pattern as the other
  two subdomain-hygiene checks. See
  `NsTakeoverDecisionLogic`/`NsTakeoverChecker` (worker) and
  `SubdomainIngestionService` (central-server).

- ~~Secret-pattern scanning inside already-exposed files~~ **Done.** New
  `SecretPatternScanner` (worker, hand-written patterns - same reasoning as
  the Wappalyzer-GPLv3 call on the fingerprinting item: no existing
  signature database to license-check, so nothing to pull in) re-greps the
  body `ExposedPathFetcher` already downloaded for `EXPOSURE_ENV_FILE` /
  `EXPOSURE_GIT_CONFIG` / `EXPOSURE_AWS_CREDENTIALS` - no new network calls -
  for AWS key formats, private-key blocks, Slack/GitHub/Stripe tokens,
  credential-embedded URLs, and generic high-entropy `key=value` assignments.
  A match adds a new `EXPOSURE_LIVE_SECRET_DETECTED` (Critical) finding,
  reported per source file (`hostname + " (.env)"` etc., same
  affected-asset-disambiguation trick the alt-port Docker/Elasticsearch
  checks already use) so an .env and a .git/config on the same host get
  independent dedup keys. Evidence stores only pattern names and a
  first-4/last-4-chars redacted preview, never the full matched string -
  findings are themselves persisted and displayed, so storing the live
  secret there would just add a second leak surface. Tried to live-verify
  against the `juiceshop.local` practice target (added a synthetic `/.env`
  to `juiceshop-proxy/nginx.conf`, confirmed by direct `curl` it served the
  intended bytes) but the attempt itself proved this module can't be
  exercised that way: `juiceshop.local` resolves to a private Docker IP,
  which `SafeAddressValidator`'s SSRF guard correctly refuses to connect to
  for every Tier 1 HTTP module, not just this one (confirmed `HTTP_HEADERS`/
  `TLS_ANALYSIS`/`TECH_FINGERPRINT` fail the same way against it already,
  unrelated to this change) - reverted the nginx fixture rather than leave
  untestable dead code in place. Verified instead via unit tests built
  against that exact real response format (`worker/.../SecretPatternScannerTest`,
  11 cases, plus new `ExposedPathDecisionLogicTest` cases covering all three
  source files), a full worker+central-server test run, and a real container
  rebuild/redeploy + Flyway migration (`V27`) applied against live Postgres.

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