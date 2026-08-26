# TODO

Backlog of concrete, not-yet-scheduled work. Not a roadmap - just things worth doing that haven't been picked up yet.

- **WordPress fingerprinting + version-based vulnerability correlation.**
  `TechDecisionLogic` (worker `modules/fingerprint`) doesn't currently detect
  WordPress at all - no check for `/wp-json/`, `wp-content`/`wp-includes`
  paths, the `<meta name="generator" content="WordPress X.Y.Z">` tag, or
  `readme.html`'s version string. Add a detection path that identifies
  WordPress and extracts its version the same way other technologies are
  reported (`Technology(name, category, version)`), and this plugs straight
  into the vulnerability pipeline that already exists for it -
  `ProductSlugMapper` already maps `"WordPress"` to NVD's `wordpress` CPE
  product slug, so once a versioned WordPress `Technology` is emitted,
  `VulnerabilityCorrelationScheduler`/`CVE_CORRELATION` should pick it up
  with no further wiring. Also worth considering while building this:
  plugin/theme version disclosure (a very common real-world WordPress
  exposure) is a natural follow-on, not just core version.

- **Client-side JS library fingerprinting.** Same pattern as the WordPress
  item above: detect jQuery/Bootstrap/etc. versions from script tags/CDN
  URLs in `TechDecisionLogic`, emit a versioned `Technology`, and the
  existing CVE correlation pipeline picks it up for free.

- **Other CMS platform fingerprinting** (Drupal, Joomla, Magento). Same
  detection pattern and payoff as WordPress - `ProductSlugMapper` would need
  a slug entry for each, same as it already has for WordPress.

- **Cloud storage bucket misconfiguration checks** (public S3/GCS/Azure Blob
  buckets, discovered via passive DNS/CT correlation - no brute-forcing).
  This was in the original design as a stretch item and never got built.
  Common, severe finding class that's currently a blind spot.

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