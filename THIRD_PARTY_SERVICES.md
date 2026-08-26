# Third-Party Services

Every external network service the deployed application calls out to while
operating — as opposed to the open-source *software* it's built from, which
is covered by [NOTICE](NOTICE). These carry their own terms of service and
(where relevant) rate limits, not a software license, which is why they're
tracked separately.

This list excludes:
- **The scan target itself.** Almost every module (HTTP header fetch, TLS
  fetch, exposure/document checks, port scan, nuclei, the ZAP spider, the
  MTA-STS check) connects directly to whatever hostname a target is tracking
  — that's the product, not a third-party dependency.
- **Build-time-only services**, e.g. the `nuclei-templates` GitHub repo
  fetched while building the worker Docker image. Nothing in the running
  application talks to it.
- **Bloodhound's own docker-compose services** (`zap`, `postgres`, etc.) and
  dev/test-only fixtures (`juice-shop`, `juiceshop-proxy`, `saml-test-idp`)
  — internal to the deployment, not third parties.

## Always on

These run automatically as part of normal Tier 1 scanning or the background
CVE-correlation scheduler — no configuration needed to enable them.

| Service | Used by | Purpose |
|---|---|---|
| Cloudflare `1.1.1.1` (DNS resolver) | `DnsRecordFetcher`, `DnsZoneFetcher`, `SubdomainDnsResolver`, `AsnFetcher`, typosquat checking | Every DNS record lookup (A/AAAA/CNAME/NS/TXT/CAA/DNSKEY) — bypasses the container's local resolver for complete/correct large-TXT and DNSKEY answers |
| crt.sh | `CrtShSource` (subdomain enum + CT monitoring) | Certificate-transparency-based subdomain discovery |
| IANA RDAP bootstrap + per-TLD RDAP/WHOIS servers | `WhoisFetcher` | Domain registration lookup (RDAP first, falls back to raw WHOIS via `whois.iana.org` referrals) |
| Team Cymru (DNS-based ASN lookup) | `AsnFetcher` | Passive hosting-provider/ASN enrichment for fingerprinted hosts |
| subfinder's own bundled passive sources | `SubfinderCliSource` | Passive subdomain enumeration — subfinder itself decides which free/keyless sources to query (crt.sh, hackertarget, rapiddns, etc.); not enumerable from this codebase since no API keys are configured for it |
| NVD (CVE API 2.0) | `NvdClient` | CVE lookup by fingerprinted product+version |
| OSV.dev | `OsvClient` | Human-readable CVE description enrichment |
| CISA Known Exploited Vulnerabilities catalog | `KevCatalogFetcher` | Flags CVEs known to be actively exploited in the wild |
| AWS S3 / Google Cloud Storage | `CloudBucketChecker` | Only contacted when a discovered subdomain's CNAME points at one — checks whether the bucket is publicly listable |

NVD/OSV/KEV all run on `VulnerabilityCorrelationScheduler`'s background tick
once any fingerprint data exists — not gated by an API key, all three are
free/keyless.

## Optional (feature-gated)

Disabled by default; the feature makes zero calls to these until configured.

| Service | Gate | Purpose |
|---|---|---|
| Have I Been Pwned API v3 | `HIBP_API_KEY` env var | Domain breach correlation — also requires the domain to be separately verified in the operator's own HIBP account, or returns 403 regardless of key validity |
| Slack Incoming Webhooks | Per-organization webhook URL, set in Admin settings | Posts scan-completion/finding notifications to a configured channel |
| Google Fonts (`fonts.googleapis.com`, `fonts.gstatic.com`) | None — loaded unconditionally by the frontend, but cosmetic only | `JetBrains Mono`/`Orbitron` webfonts; Tailwind config has local fallback stacks if unreachable |

## Adding a new one

Check the license/terms of service before wiring in a new external service,
same as any new OSS dependency (see NOTICE) — and add it to this file in the
same commit that adds the integration.
