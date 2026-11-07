# Bloodhound security review and rules parity

Reviewed 2026-10-16 from the source tree at `/home/joe/workspace/bloodhound`. No code was changed. Nothing was exploited against a running stack. Line numbers refer to the tree as it was on that date.

An older note, `groksec.md`, describes several high-severity bugs that the current code has already closed (job results ingested before the worker lease, a global rules toggle, the MCP login matcher shadowing the SAML ACS, Tier 2 authorization on non-`OWN` targets, Nuclei talking to public Interactsh, plaintext SSO handoff tokens, and access JWTs that trusted stale role claims). Those are not re-filed below. Treat this file as the current review.

## Bottom line

The control plane is in better shape than a typical self-hosted scanner. Tenant lookups are org-scoped, Tier 2 is gated on an attested `OWN` target, worker result ingestion now checks the job lease first, secrets at rest are hashed, and the Java HTTP client refuses private addresses and re-checks redirects. What is left is the scan processes on the API's network, and a few job-state holes behind the worker key.

Fix these before the worker is pointed at a hostname you do not control:

1. Katana runs on every Tier 1 scan, inside the worker, on the same Docker network as `central-server`. It fetches linked URLs that are not the target. A competitor domain, which this product exists to monitor, can aim that crawl at the API. Nuclei has the same shape on an authorized deep scan: the Java HTTP client checks addresses, and these two subprocesses do not.
2. `fail()` updates a job by id only, so a late failure report can put a finished or cancelled job back on the queue. Revoking Tier 2 authorization does not cancel a deep scan that was already queued. The worker fleet also shares one key that can claim any tenant's jobs.

On detection coverage, Bloodhound is a real external ASM product for DNS, TLS, headers, a curated exposure list, brand lookalikes, and (on authorized targets) a full Nuclei corpus plus ZAP. It is not at parity with commercial EASM on asset attribution, cloud-account inventory, authenticated application testing, or the long tail of takeover and typosquat tricks. Tier 2 Nuclei is where most CVE depth lives, and it is also where the safety and noise problems live.

---

## How this was reviewed

Read-only inspection of `central-server`, `worker`, `webui`, `bloodhound-common`, Flyway migrations under `central-server/src/main/resources/db/migration`, and `docker-compose.yml`. Rules were taken from `rules_catalog` seeds plus the worker decision classes that actually emit them. Vendor comparisons use those rules and public descriptions of the other tools (ProjectDiscovery nuclei-templates layout, dnstwist's documented fuzzers, and published EASM product descriptions). Vendor marketing was not treated as a verified feature list.

---

# Part 1. Security review

## What already holds

These were checked in the current source and are not open bugs.

- **Tenant isolation on the data API.** Target, finding, and authorization lookups that were inspected go through `findByIdAndOrganization` (or an equivalent org predicate), not a bare id.
- **Worker results cannot be written for a job the caller does not hold.** `JobLifecycleService.result` locks the row with `findByIdOwnedByForUpdate` before ingestion. An empty findings list, which the reconciler treats as "resolved", no longer lands before that check. `JobResultRequest` caps findings at 2,000, raw metadata at 500 entries, and log lines at 5,000.
- **Tier 2 stays on `OWN` targets.** `TargetAuthorizationController.authorize` returns 403 unless `targetType` is `OWN`.
- **Rules can be disabled per organization.** `PATCH` writes `org_rule_overrides`, not a global update of `rules_catalog`.
- **Session tokens track live user state.** `JwtAuthenticationFilter` trusts only the user id in the access token and reloads status, role, org, and email on each request. A disabled user fails closed on the next call. SAML login also rejects a non-`ACTIVE` user.
- **SSO handoff stores a 60-second code, not the refresh token.** Tokens are minted at exchange time. Refresh tokens in the main table are hashed. API, SCIM, and worker keys are stored as SHA-256. Passwords use BCrypt cost 12.
- **MCP login no longer swallows the SAML ACS.** The authorization-server chain matches exact `/login`, not `/login/**`. The ACS remains `/login/saml2/sso/{slug}` on the SAML chain. Dynamic client registration requires consent, PKCE (`requireProofKey(true)`), and the consent page shows the redirect URI. The client name is HTML-escaped.
- **The Java HTTP client is SSRF-aware.** `SafeHttpGet` checks every redirect hop and fails closed if the host does not resolve. AXFR checks the nameserver address before connecting and pins that IP. The MTA-STS fetch uses `SafeHttpGet` with redirects disabled, which is also what RFC 8461 requires. Katana and Nuclei do not go through this client. That is finding 1 and finding 2, not a hole in `SafeHttpGet`.
- **Nuclei no longer calls ProjectDiscovery Interactsh.** The invocation passes `-no-interactsh`. Hostnames that start with `-` are rejected before they become argv. DoS and fuzz template tags are excluded.
- **Disabling a user in the admin UI revokes refresh tokens and API keys** (`OrgUserController`). That path is fine. SCIM is the path that is not, below.
- **Network segmentation in Compose is real.** Postgres is on an internal `db_net` with only `central-server`. Juice Shop is behind the `dev-fixtures` profile and on an internal `targets_net`. ZAP is not on `app_net`. Worker, central-server, and webui images are designed to run as uid 1000. Actuator exposure on the worker is `health` only.
- **API keys are read-only at the filter chain.** `ROLE_API_KEY` is accepted only for `GET` on an explicit allowlist. A leaked key cannot call scan, authorize, or user-admin routes through that chain.
- **Cookies.** The refresh cookie is `HttpOnly`, `SameSite=Lax`, and scoped to `/api/auth`. The SPA does not use `dangerouslySetInnerHTML`. CSV export guards formula injection.
- **Subprocess argv is a list, not a shell string.**

## Open findings

### 1. Nuclei is not bound to the address that passed the SSRF check

**Severity: High** for any Tier 2 scan of a host the target owner does not fully trust. That includes a compromised `OWN` application, which is a normal reason to run a deep scan.

`NucleiFetcher` calls `SafeAddressValidator.requireSafeIfResolvable(hostname)` and then execs `nuclei -target <hostname>`. The comment in that class is explicit: naabu and zgrab2 are handed a pre-resolved address, and Nuclei is not, because it needs the name for SNI and the Host header. Nothing in the argv disables redirects or pins the dial address. The template directory is the full corpus baked at image build (`/opt/nuclei-templates`), minus tags `dos` and `fuzz`. That corpus includes `javascript`, `code`, `headless`, and `network` templates, not only HTTP checks.

The worker container is on `app_net` together with `central-server` (`docker-compose.yml`). A target that redirects, or that rebinds DNS after the one-shot check, can cause Nuclei to open connections to the API. ZAP does not have this path: it sits on `scan_net` and `targets_net`, not on `app_net`.

Practical impact if a target is hostile:

- Nuclei findings about the control plane get stored against the customer target.
- The Nuclei child inherits the worker environment, including `WORKER_API_KEY`, `ZAP_API_KEY`, and `SCREENSHOTTER_API_KEY`. A template or parser bug that becomes code execution is a control-plane credential, not just a crashed scan. This review did not identify a current Nuclei CVE. The inheritance and the network placement are what make that class of bug worse here than it would be in a throwaway scanner VM.

`-no-interactsh` closed the data-leak half of the earlier finding. It did not close this half.

### 2. Katana fetches off-target URLs from the control-plane network

**Severity: High.** This one does not wait for Tier 2. `SUBDOMAIN_ENUM` is queued for every target type, including `COMPETITOR` and `WATCHLIST`. Those sites are not yours.

`KatanaCliSource.command` runs `katana -u https://<apex>/` with `-jc`, `-fs rdn`, a 45-second crawl cap, and a 500-page cap. Nothing calls `SafeAddressValidator` before `ProcessBuilder.start()`. The class comment says what `-fs rdn` actually does: it stops katana recursing off the root domain, and it still fetches the out-of-scope URLs it finds. The comment names fonts.googleapis.com and facebook.com from a live crawl. `inScope` is applied to the hostnames that are saved, not to the requests that are sent.

The worker is on `app_net` with `central-server` and `webui` (`docker-compose.yml`). A page on a monitored apex can reference `http://central-server:8080/...`, port included. Health and the OpenAPI spec on that port do not require a token. Katana will request the URL it was given. The same is true of any other name that resolves on `app_net`.

`ProcessBuilder` does not clear the environment. The katana child inherits `WORKER_API_KEY`, `ZAP_API_KEY`, `SCREENSHOTTER_API_KEY`, and `HIBP_API_KEY`. This review did not find a katana bug that reads those variables. A bug in the crawler would be holding the worker credential, which finding 5 describes. The SSRF itself does not need that bug. It is a GET from the worker's network position.

The apex is checked for a private address only when the target is created (`TargetController.rejectUnsafeHostname`). Katana resolves the name itself on each scan. A domain whose DNS you do not operate can answer with a different address by then. That is the Nuclei gap, on a module that is always on, against hosts you already classified as someone else's.

### 3. A late `fail()` can reopen a finished or cancelled job

**Severity: Medium.** Requires the worker key and the `workerId` that holds the lease. It does not require a user JWT.

`ScanJobRepository.fail` selects the row only when `claimed_by` matches and status is `CLAIMED` or `RUNNING`, then updates by `id` alone:

```sql
UPDATE scan_jobs SET status = 'PENDING', ... WHERE id = ?
```

The terminal `FAILED` / `UNREACHABLE` update is the same shape. `complete()` does include `claimed_by` and status in the `UPDATE`. `fail()` does not.

`result()` is `@Transactional` and holds that row `FOR UPDATE` for the whole ingest. `JobLifecycleService.fail` is not transactional. It loads the job with `findById` (no lease check), then `ScanJobRepository.fail` does its own `SELECT` and, as a later statement, the `UPDATE`. Under Postgres read committed that `SELECT` does not wait on the result lock, so it can observe `CLAIMED` or `RUNNING`, block on the `UPDATE`, and after `result()` commits `COMPLETE` overwrite it to `PENDING` or `FAILED`. The same update can overwrite `CANCELLED`. The comment on `ScanJobRepository` says a cancel makes a later `fail` a no-op because `fail` guards on status. That is true of the `SELECT`, not of the `UPDATE`.

The service method then always closes the attempt row, and on `FAILED` or `UNREACHABLE` it calls `checkAndCompleteRun`. A raced overwrite does not only put the job back on the queue. It can also record the successful attempt as failed and close the run from that status, after the findings have already been written.

Effect: a deep scan the operator cancelled, or a job that already wrote findings, becomes claimable again and will be scanned. The worker key is enough. The window is the length of ingest, which for Nuclei or ZAP is minutes, not a single interleaving.

### 4. Revoking Tier 2 authorization does not stop a scan already queued

**Severity: Medium.** This is the gap between the attestation gate and the thing that sends payloads.

`TargetController.deepScanNow` is the only check that `authorization_status` is `AUTHORIZED`. `ScanRunService.createDeepScan` documents that it does not check again. `claim` does not join `targets.authorization_status`. `TargetAuthorizationController.revoke`, and a `PATCH` that changes the target type away from `OWN`, flip the status to unauthorized and do not cancel `scan_jobs`.

A deep scan that has already been queued keeps running Nuclei, full-port scan, and ZAP after revoke. A job a worker has already started cannot be interrupted by cancel either. The comment on cancel says the in-flight work finishes. Revoke does not even mark the queued rows cancelled.

The authorize call itself is in good shape: `OWN` only, attestation required, org-scoped, admin or analyst. The hole is everything after the jobs exist.

### 5. One shared worker key is a cross-tenant write credential

**Severity: High** if `WORKER_API_KEY` leaks. **Accepted architecture** if that secret is treated like a root credential and is not a placeholder.

Every worker presents the same key. `workerId` is whatever the client sends. The lease check fixed finding 1 of the old review, so a caller must actually claim the job before posting results. The key still lets its holder claim any org's queued jobs, post findings, resolve open findings by posting an empty set for that module and scope, and fail jobs. Placeholder detection for this key is a startup warning plus an admin banner, same as `JWT_SIGNING_KEY` (`JwtService`, `WorkerCredentialBootstrapRunner`). The process starts anyway.

There is no per-worker credential and no per-org scope on the key.

### 6. Headless Chrome renders attacker pages on the scanner network

**Severity: Medium.** This one fires on Tier 1, not only on authorized deep scans.

Typosquat monitoring screenshots newly registered lookalike domains. Those sites are, by definition, controlled by whoever registered them. `screenshotter` (browserless Chromium) is on `scan_net` with the worker and ZAP. It is not on `app_net`, so it cannot resolve `central-server` or Postgres. A page it loads can still ask Chromium to connect to `zap:8080` and to the worker's port 8081.

ZAP requires an API key (`api.disablekey=false`). The worker only exposes the health endpoint. So this is not a free pass to the database. It is still a browser, parsing untrusted HTML and JavaScript, with a route to the active-scan engine. A Chromium exploit in that container is the realistic outcome, not a clever HTTP request.

### 7. Refresh-cookie `Secure` flag follows the app's own idea of HTTPS

**Severity: Medium** on a TLS-terminating reverse proxy. **Not an issue** for direct HTTPS or for local HTTP.

`AuthProxyController` sets `Secure` from `HttpServletRequest.isSecure()`. The comment in that method says Spring will only see `X-Forwarded-Proto` after someone turns on forward-headers. A deployment that terminates TLS in front and forgets that setting stores the 30-day refresh cookie without `Secure`.

### 8. SCIM deprovision does not revoke credentials, and SCIM users cannot log in

**Severity: Low today, High if SAML is later linked to SCIM users.** The two halves are one identity bug.

`ScimUsersController` replace, patch, and delete only flip `users.status`. They never revoke refresh tokens or API keys. The admin UI path does both.

That missing revoke is not currently reachable for a SCIM user:

- SCIM insert sets `identity_source = 'SCIM'` and no password hash.
- Local login only matches `identity_source = 'LOCAL'`.
- SAML JIT only matches `identity_source = 'SAML'`, first by NameID, then by email (`UserRepository.findOrCreateSamlUser`). A SCIM row is invisible to that lookup. The same email then collides on `uq_users_org_email` if SAML tries to create a second row.

So a SCIM-provisioned user, as the code stands, cannot open a session and cannot mint an API key. Deprovision has nothing to revoke. It also means the documented SCIM-plus-SSO setup does not actually sign those users in.

If login is later fixed by matching the SCIM row, the missing revoke becomes the offboarding bug: `ApiKeyAuthFilter` does not check that the key's creator is still `ACTIVE`, and a refresh token that was never revoked works again the moment the user is reactivated. `ApiKeyController.create` allows any `ADMIN`, `ANALYST`, or `VIEWER` to mint a key.

Related, and already live for SAML users: on every login the matched row's email, display name, and `external_id` are overwritten from the assertion. The email fallback exists so a transient NameID does not duplicate the user. It also means an IdP that lets a user influence the configured email attribute can rebind their NameID onto another SAML user in that org. That is safe only when the IdP treats that attribute as verified and immutable.

### 9. SCIM `count` is not capped

**Severity: Low.** The caller already holds a SCIM token for that org.

`ScimUsersController.list` passes `count` straight into SQL `LIMIT`. A huge value makes the service load every SCIM user row for the org. It does not cross tenants.

### 10. A subdomain name is not required to be a hostname

**Severity: Medium.** The practical reach is smaller than the guard bypass, because of where ZAP and the screenshotter sit.

Target creation rejects anything that fails `HOSTNAME_PATTERN` (labels of letters, digits, and hyphens). `SubdomainController.add` does not. It lowercases, trims, and accepts the string when it equals the apex or ends with `.<apex>`. `SecurityConfig` allows that `POST` to `ADMIN`, `ANALYST`, and `VIEWER`.

`requireSafeIfResolvable` treats "does not resolve" as success. A value such as `central-server#.example.com` does not resolve, so the check returns. `java.net.URI` treats `#` as the start of the fragment, so the host in that URL is `central-server`, which Docker DNS on `app_net` does resolve.

`SafeHttpGet` is not bypassed. It checks `URI.getHost()` and fails closed, including on a private address, and it also fails closed when the host does not resolve. Nuclei's reachability probe uses `SafeHttpGet`, so this string does not start a Nuclei scan of the API.

ZAP and the screenshotter check the raw string, then send `https://` plus that string to a parser that drops the fragment. Both are off `app_net` (ZAP is on `scan_net` and `targets_net`, the browser on `scan_net` only), and neither URL builder sets a port. What they can open today is whatever answers on port 80 or 443 from those networks: their own loopback, and the bridge gateway. Not `central-server` by name. The guard still does not look at the host that will be dialed. Rejecting names that fail `HOSTNAME_PATTERN` closes it. So does not using the fail-open resolver on a string that is not a DNS name.

### 11. Nuclei and ZAP evidence keeps what the check extracted

**Severity: Medium.** This is storage of target secrets, not a missing authentication check.

Nuclei is started with `-omit-raw`, which drops the raw request and response. `NucleiFindingMapper` still copies `curl-command` and `extracted-results` into the finding. `ZapAlertMapper` copies ZAP's `evidence` and `param`. Exposure templates are written to pull out tokens, keys, and file snippets. Those strings are stored and shown to every role that can read findings, API keys included. The first-party secret rules redact. These two families do not.

## Residual risks, already visible in the code

| Item | Why it is still here |
|---|---|
| ZAP API key on the process command line | `docker-compose.yml` documents this. `docker top` on the host can read it. The image has no env-var alternative in use. |
| Juice Shop can open TCP to ZAP | Only with the `dev-fixtures` profile. They share `targets_net`. The API key is the remaining control. Do not run that profile on a shared host. |
| `central-server` publishes `:8080` | Swagger, dynamic client registration, and the API are on the host interface in the default Compose file. The comment says to drop the `ports:` block in production. Webui on `:8090` is the intended browser entry. |
| Placeholder JWT and worker secrets warn instead of refusing to boot | Deliberate, so a deploy does not die mid-use. Safe only if the admin banner is actually acted on before the port is reachable. |
| `SafeHttpGet` is not a full DNS-rebinding defense | The class says so. Each redirect host is checked. A record that changes between check and connect is not. The CORS probe in `HttpHeaderFetcher` is a second request to the same name with no check of its own, after a `SafeHttpGet` that already succeeded. Nuclei and Katana are the much larger instance of the same gap. |
| AXFR stops at 50,000 records, not at a byte count | `DnsZoneFetcher.MAX_AXFR_RECORDS`. The records are held in memory. The worker cgroup limit is 2G per replica. A nameserver the target delegates to can OOM that replica. It cannot reach the other two, or Postgres. |
| Document "same site" includes shorter suffixes | `DocumentLinkDecisionLogic.isSameSite` is true when either host is a dot-suffix of the other. `www.example.com` will download `https://com/file.pdf` if the homepage links it. The fetch still goes through `SafeHttpGet`. The parser is PDFBox `Loader.loadPDF` and POI `OPCPackage.open` on up to 20MB, with no zip-bomb setting in this class. Library defaults apply. |
| The per-host rate limit covers three fetchers | `HostnameRateLimiter` is 12 requests/second per worker JVM, on exposure checks, document fetches, and bucket brute force. An interrupt returns and the caller continues. Buckets are never removed. naabu is invoked at its own `-rate`. Three replicas do not share a bucket. |
| ZAP's spider is not confined to the seed host | The spider call is `url`, `maxChildren=10`, `recurse=true`. No `subtreeOnly`, no context. A comment in `ZapScanRunner` records a live crawl requesting Trustpilot, Vimeo, and Facebook. The active scan is then started against the seed URL only. Default attack rules stay enabled except the noise ids in `ZapNoiseRules` (active `10104`; passive `10015`, `10050`, `10096`, `10109`, `10112`). |
| One shared ZAP, and the session reset can fail | `startFreshSession` logs and continues. A failed reset leaves the previous job's history in that process. Alerts are requested with `baseurl` set to this job's seed. The claim path already allows only one active-scan job at a time. |
| A few address forms are not unwrapped | `isSafeToConnect` unwraps IPv4-compatible addresses and the well-known NAT64 prefix `64:ff9b::/96`. It does not unwrap 6to4 (`2002::/16`) or the local NAT64 prefix `64:ff9b:1::/48`. `198.18.0.0/15` and `240.0.0.0/4` are not special-cased. Whether any of those route is a property of the host, not of this class. |
| Compose does not drop capabilities | Memory and CPU limits are set, and central-server, webui, and the worker run as uid 1000. There is no `cap_drop`, no `no-new-privileges`, and no read-only root filesystem. ZAP is the usual ZAP image (root, API key on the command line). |
| MCP dynamic registration does not restrict the redirect URI | Consent, PKCE, and an HTML-escaped redirect URI on the consent page are enforced in `ConsentRequiringRegisteredClientRepository`. Nothing in this app requires `https` or a loopback host. A native MCP client often needs a custom scheme, so a blanket https rule would break the supported login. The remaining case is a user approving a client whose redirect is `http://` or an internal name. The code is delivered to the user's browser, not fetched by the server. |
| SAML AuthnRequests are unsigned | `wantAuthnRequestsSigned(false)` in `DbRelyingPartyRegistrationRepository`. The IdP certificate is used to verify assertions. Request signing is hardening, not a broken login. |
| Access token lifetime | Live user lookup removed the "disabled admin keeps admin for 15 minutes" bug. A stolen access token still works until it expires, for a user who is still `ACTIVE`. That is normal for a stateless JWT. |
| No MFA | Previously declined as a product decision. It remains a gap against commercial consoles and against a stolen password. Not re-opened here as a defect. |
| Login lockout is per email, in memory | Many accounts can still be guessed at the per-account limit. One process only. |
| Worker-supplied finding severity and evidence | After the lease check, ingestion trusts the worker's payload. That is consistent with a trusted fleet and is the same blast radius as finding 5. |

## Deployment notes that are not code bugs

- `.env` is gitignored. This review did not open it and does not know whether the live values are still examples.
- Postgres is not published to the host. Good.
- Bootstrap admin password is whatever `BOOTSTRAP_ADMIN_PASSWORD` is. Weak-password rejection applies to later password changes, not to that initial value.

---

# Part 2. Rules parity

## What the rules set actually is

There are about **126 first-party rules** in `rules_catalog`, plus two open-ended families that are not seeded one-by-one: `NUCLEI_*` and `ZAP_ALERT_*`. Those two are the Tier 2 web-application category.

The numeric score (0–100, letter grade) uses only seven categories, from `ScoringEngine`:

| Category | Weight |
|---|---|
| Exposure | 0.22 |
| TLS | 0.17 |
| DNS | 0.17 |
| Web application (Nuclei and ZAP) | 0.15 |
| Network | 0.13 |
| Headers | 0.08 |
| Subdomain hygiene | 0.08 |

WHOIS, breach, brand, and compound findings are stored and shown. They do not move that score. `INFO` findings score zero points. Later findings of the same severity in a category are discounted (factor 0.7).

The Compare page defaults to a second score, not the full one (`ComparePage` uses `tier1` unless `mode=full`). `ScoreSnapshotService` builds it by dropping every rule with `emitted_by_tier1 = false` and every `WEB_APP` finding. That category exclusion is how Nuclei and ZAP stay out of the fair number even though they have no catalog row. The catalog flags, from `V12` and `V65`, are anonymous FTP, the full-port-range summary, and brand-name bucket brute force. **Exception:** `NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED` is only produced by the deep port scan (`V73` says so, and does not set the flag), so a deep-scan-only finding still moves the number Compare shows by default.

### DNS and email (19)

Emitted by the DNS posture module unless noted.

| Rule | Severity | What it actually checks |
|---|---|---|
| `DNS_SPF_MISSING` | High | No `v=spf1` TXT at the apex. |
| `DNS_SPF_TOO_PERMISSIVE` | Medium | First SPF record ends in `+all` or `?all`. `~all` is allowed. |
| `DNS_SPF_MULTIPLE_RECORDS` | High | More than one SPF TXT. |
| `DNS_SPF_LOOKUP_LIMIT_EXCEEDED` | High | Recursive include / a / mx / ptr / exists / redirect count over 10. |
| `DNS_SPF_INCLUDE_DANGLING` | High | An `include:` target has no SPF of its own. |
| `DNS_DMARC_MISSING` | High | No `v=DMARC1` at `_dmarc`. |
| `DNS_DMARC_POLICY_NONE` | Medium | The record string contains `p=none`. Not a parsed tag. |
| `EMAIL_DMARC_RUA_MISSING` | Low | A DMARC record with no `rua=`. |
| `EMAIL_DMARC_PCT_BELOW_100` | Low | Explicit `pct` below 100. A missing `pct` counts as 100. |
| `DNS_CAA_MISSING` | Low | No CAA records. No check of `issue` or `issuewild` contents. |
| `DNSSEC_NOT_ENABLED` | Medium | No DNSKEY. Presence only. No DS or RRSIG validation. |
| `EMAIL_MTA_STS_MISSING` | Medium | Missing `_mta-sts` TXT, or the policy URL did not return 2xx. `mode=` is not parsed, so `mode=testing` counts as present. |
| `EMAIL_TLS_RPT_MISSING` | Low | No `_smtp._tls` TXT. |
| `EMAIL_BIMI_ABSENT` | Info | No `default._bimi` TXT. |
| `DNS_DKIM_NOT_DETECTED` | Low | No TXT at selectors `default`, `google`, `selector1`, `selector2`, `k1`, `dkim`. |
| `DNS_MX_TO_DANGLING_HOST` | High | An MX hostname has no A or AAAA. |
| `DNS_SOA_SERIAL_STALE` | Low | SOA serial looks like `YYYYMMDDnn` and that date is at least two years old. |
| `DNS_ZONE_TRANSFER_ALLOWED` | Critical | A listed nameserver answered unauthenticated AXFR. |
| `DNS_NS_LAME_DELEGATION` | Medium | A reachable nameserver was not authoritative for the apex. |

### TLS (16)

| Rule | Severity | What it actually checks |
|---|---|---|
| `TLS_CERT_EXPIRED` | Critical | `notAfter` is past. |
| `TLS_CERT_EXPIRING_SOON` | Medium | Expires within 30 days. |
| `TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN` | High | Chain does not validate to a public root. |
| `TLS_CERT_HOSTNAME_MISMATCH` | High | SAN/CN does not cover the name. Skipped when the cert has no DNS names. |
| `TLS_CERT_SIGNATURE_ALGORITHM_WEAK` | High | Signature algorithm name contains MD5, MD2, or SHA1. |
| `TLS_CERT_KEY_TOO_SHORT` | High | RSA or DSA under 2048 bits. Elliptic-curve keys are not judged. |
| `TLS_WEAK_PROTOCOL_SUPPORTED` | High | SSLv3, TLS 1.0, or TLS 1.1 accepted. One finding per protocol. |
| `TLS_POODLE_VULNERABLE` | Critical | SSLv3 accepted, labeled as CVE-2014-3566. No separate padding-oracle proof. |
| `TLS_WEAK_CIPHER_SUITE` | Medium | A negotiated or probe suite name contains RC4, DES, 3DES, NULL, EXPORT, or MD5. |
| `TLS_NO_FORWARD_SECRECY` | Medium | A pre-1.3 suite without ECDHE or DHE. Not applied to TLS 1.3. |
| `TLS_1_3_NOT_SUPPORTED` | Low | The host did not negotiate TLS 1.3. |
| `TLS_NO_HSTS` | Medium | HTTPS responded and `Strict-Transport-Security` is absent. |
| `TLS_HSTS_SHORT_MAX_AGE` | Low | `max-age` under six months, or `includeSubDomains` missing. |
| `TLS_HSTS_PRELOAD_NOT_ELIGIBLE` | Low | `preload` is set but max-age or includeSubDomains would fail the preload bar. |
| `TLS_HSTS_NOT_ON_PRELOAD_LIST` | Low | `preload` is set and hstspreload.org does not say `preloaded`. A lookup failure is silent. |
| `TLS_CT_UNEXPECTED_ISSUER` | Medium | Issuer DN does not contain one of a hardcoded CA substrings (Let's Encrypt, DigiCert, Sectigo, and others). This is not a certificate-transparency log check. The name overclaims. |

Not checked, and present in testssl.sh / SSL Labs style reviews: Heartbleed, ROBOT, DROWN, Logjam, BEAST, CRIME, TLS compression, OCSP stapling, must-staple, session-ticket lifetime, DANE/TLSA, and whether the certificate was actually submitted to a CT log.

### HTTP headers and cookies (15)

Presence checks use the header name. A CSP `frame-ancestors` directive does not satisfy `X-Frame-Options`. `Content-Security-Policy-Report-Only` does not count as CSP.

| Rule | Severity | Notes |
|---|---|---|
| `HEADER_CSP_MISSING` | Medium | Header absent. |
| `HEADER_CSP_WEAK_POLICY` | Medium | `unsafe-inline` or `unsafe-eval` anywhere in the policy, including `style-src`, or a bare `*` in `script-src` or `default-src`. This will fire on a large share of real sites. |
| `HEADER_XFO_MISSING` | Low | |
| `HEADER_XCTO_MISSING` | Low | Presence only. The value is not required to be `nosniff`. |
| `HEADER_REFERRER_POLICY_MISSING` | Info | |
| `HEADER_PERMISSIONS_POLICY_MISSING` | Info | |
| `HEADER_COOP_MISSING` | Info | |
| `HEADER_CORP_MISSING` | Info | |
| `HEADER_SERVER_BANNER_VERBOSE` | Info | `Server` or `X-Powered-By` matches a `digit.digit` version. A bare product name is ignored. |
| `COOKIE_MISSING_SECURE_FLAG` | Medium | The whole `Set-Cookie` line lacks the substring `secure`. A value that happens to contain that word can suppress the finding. Same pattern for the next two. |
| `COOKIE_MISSING_HTTPONLY_FLAG` | Medium | Substring `httponly`. |
| `COOKIE_MISSING_SAMESITE` | Low | Substring `samesite`. `SameSite=None` counts as present. |
| `COOKIE_MISSING_HOST_PREFIX` | Info | Cookie is `Secure` but the name is not `__Host-` or `__Secure-`. |
| `HTTP_NO_HTTPS_REDIRECT` | Medium, or Low | Port 80 returns a successful response, or redirects somewhere that is not `https://`. The non-HTTPS redirect case is lowered to Low. |
| `CORS_CREDENTIALED_ORIGIN_REFLECTION` | High | `Access-Control-Allow-Origin` echoes a probe origin and credentials are allowed. A bare `*` is intentionally not a finding. |

Mozilla Observatory also cares about `X-Content-Type-Options: nosniff` as a value, SRI, and a graded CSP. Bloodhound checks presence and one weak-CSP heuristic, not a grade.

### Exposure (about 52 first-party rules)

Tier 1 path probes compare the body to a random-path baseline, then require a signature. That is the right shape and it is narrower than people expect from the word "exposure".

Covered with high or critical severity when the signature matches: Spring actuator heapdump, env, beans, mappings, configprops, threaddump, loggers, and the actuator index; `.git/config`; `.env`; `.aws/credentials`; Jenkins script console; phpMyAdmin; Kibana; Grafana health; Elasticsearch; Redis `INFO` when auth is not required; Docker API on 2375; Consul; Mongo Express; Traefik's old rawdata API; H2 console; Laravel Telescope and Whoops/Ignition debug pages; ASP.NET trace.axd and ELMAH; Adminer; phpinfo; Prometheus `/metrics`; directory listing on a fixed set of paths; `.DS_Store`; backup zip/tar and SQL dump names; a PEM private key at a few fixed paths; JavaScript source maps for up to six same-host scripts; GraphQL introspection; Swagger/OpenAPI JSON.

`EXPOSURE_LIVE_SECRET_DETECTED` runs ten regexes (AWS key id, AWS secret assignment, PEM, Slack token, Slack webhook, GitHub token, Stripe key, Google API key, URL with embedded credentials, and a generic quoted secret assignment) and only on the `.env`, `.git/config`, and `.aws/credentials` bodies already fetched. Values are redacted. There is no live call to see if the key works. This is much smaller than gitleaks or the nuclei `http/exposures/tokens` tree, which has a directory per vendor.

Cloud:

- `EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING` (Tier 1): a CNAME to S3 or GCS that returns a listing. Azure is not on this path.
- `EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC` (Tier 2): guessed names against S3, GCS, DigitalOcean Spaces, Linode, Scaleway, and Azure Blob. Public listing only, not public write. The wordlist is walked across many scans, 150 names at a time, with a 14-day skip for names already tried.

Documents, from up to five homepage links with a document extension: internal path in metadata (`MEDIUM`), author or application name (`INFO`).

Version intel is not a worker rule. Fingerprints are correlated later, and only for a short product list (nginx, Apache, PHP, WordPress, jQuery, Bootstrap, Drupal):

- `TECH_KNOWN_CVE` against NVD and OSV. Severity follows the worst CVSS bucket. Catalog default is medium.
- `TECH_KNOWN_EXPLOITED_VULNERABILITY` when one of those CVEs is in CISA KEV.
- `TECH_EOL_SOFTWARE_DETECTED` and `TECH_EOL_APPROACHING` (within 90 days) from endoflife.date.

WordPress plugins can be fingerprinted. They are not CVE-mapped. A CVE in a plugin is invisible to this correlator. Nuclei may still catch a known plugin bug on a Tier 2 scan, under a different rule id.

### Network (7)

Tier 1 is a TCP connect to 35 ports, on one IPv4 and one IPv6 address: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 5984, 6379, 8080, 8443, 8500, 9092, 9200, 9300, 27017, 27018.

Only some of those become findings:

- `PORT_UNEXPECTED_OPEN_ADMIN_SERVICE` (High): 3389, 3306, 5432, 27017, 6379, 1433, 1521, 5900, 5984. The light scan does not speak the protocol. A middlebox that accepts the handshake can look like an open database.
- `PORT_OPEN_UNENCRYPTED_MGMT` (Medium): 21 or 23.
- `NETWORK_PROMISCUOUS_PORT_RESPONSE` (Info): five or more of the admin/database ports open at once. This replaces the per-port admin findings. FTP and Telnet findings still emit.
- `NETWORK_IP_KNOWN_BOTNET_C2` (Critical): a resolved address is currently "online" in abuse.ch Feodo Tracker. One feed. Shared cloud addresses will false-positive, and the finding text says so.

Not a port finding on their own, even when the connect succeeds: SSH (22), SMTP, SMB (445), Docker (2375), Elasticsearch (9200), Kafka (9092). Some of those have a separate exposure probe (Docker, Elasticsearch, Redis). SMB has neither.

Tier 2 adds a full 1–65535 connect scan (`NETWORK_FULL_PORT_SURFACE`, informational), anonymous FTP login (`NETWORK_ANONYMOUS_FTP`, critical), and weak SSH algorithms (`NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED`, high): SHA-1 key exchange groups, `ssh-rsa` and `ssh-dss` host keys, CBC / arcfour / none ciphers, MD5 or sha1-96 MACs.

### Subdomain hygiene (4)

- `SUBDOMAIN_NEW_UNEXPECTED` (Info): a name not seen before, from certificate transparency and passive DNS (subfinder), not from brute force.
- `SUBDOMAIN_DANGLING_CNAME` (Critical): CNAME matches one of 14 services and the HTTP body matches that service's unclaimed fingerprint. The list is a deliberate subset of can-i-take-over-xyz (S3, GitHub Pages, Heroku, Azure Web Apps, Zendesk, Shopify, Fastly, Bitbucket, Pantheon, Surge, Readme, Help Scout, Cargo Collective). Edge-case providers are excluded on purpose: Tumblr, WordPress.com, Netlify, Vercel, Intercom, Webflow, Ghost, CloudFront, Unbounce, Statuspage.
- `SUBDOMAIN_NS_DELEGATION_TAKEOVER` (Critical): NS hostname looks like Route 53, Azure DNS, Google Cloud DNS (`googledomains.com`), or DigitalOcean, and that server is not authoritative. NS1 and several smaller DNS hosts are absent.
- `SUBDOMAIN_WILDCARD_DNS` (Info): a random child name resolves.

Matching is substring `contains`, not a suffix. That is correct for `bucket.s3-website-us-east-1.amazonaws.com`. It can also match a name that merely embeds the fragment.

### Brand (3)

Permutations are ASCII-only, capped at 100 candidates, last-dot TLD split (so `example.co.uk` is wrong): TLD swap against a short list (`net`, `org`, `co`, `io`, `info`, `biz`, plus `cm` and `om` for `.com`), a handful of homoglyphs (`o`/`0`, `l`/`1`, `rn` for `m`, and similar), omission, duplication, transposition, hyphenation, QWERTY neighbors.

- `TYPOSQUAT_DOMAIN_REGISTERED` (High): the candidate resolves.
- `BRAND_TYPOSQUAT_MX_CONFIGURED` (Critical): it has MX.
- `BRAND_TYPOSQUAT_HOSTING_LIVE_SITE` (Critical): it serves a page. A dHash similarity percentage is stored as evidence and shown in the UI. It is not its own rule, and it does not change severity.

dnstwist, which this generator cites as the taxonomy, also does Unicode homoglyphs, bitsquatting, insertion, vowel swap, dictionary words (`login`, `secure`), a real public-suffix split, GeoIP, WHOIS dates, and an MX check that asks whether the mail server would accept mail for the real domain. Bloodhound has the MX-exists signal and the screenshot hash. It does not have the rest.

### WHOIS, breach, compound

- `WHOIS_EXPIRY_APPROACHING` (High), `WHOIS_REGISTRANT_CHANGED` (Info, needs history), `WHOIS_NO_TRANSFER_LOCK` (Medium).
- `BREACH_EMAIL_DOMAIN_IN_KNOWN_BREACH` (Medium): Have I Been Pwned domain breach, when an API key is configured. Not stealer logs, not per-mailbox, not infostealer-corpus products.
- Five compound rules, all insight-only for the score: credentials plus a path to data, Docker API plus another serious finding, an admin console on weak transport, a KEV on an already exposed host, and a source checkout next to a live secret. They require every group to match on the same asset, and one finding cannot satisfy two groups.

### Tier 2 web application, uncounted

Nuclei is the full upstream template set at image-build time, with `dos` and `fuzz` excluded and OAST disabled. Upstream's tree includes `http/cves` (through 2026 in the public repo), `http/exposures` (configs, backups, tokens, APIs), `http/technologies`, `network`, `ssl`, `javascript`, `code`, and `headless`. ProjectDiscovery's own overview counts on the order of 450 CISA KEV templates and a much larger VulnCheck set. Bloodhound does not pin a severity filter, so informational technology templates come back as findings too.

ZAP runs spider plus active scan. The spider is not limited to the seed host (no `subtreeOnly`, no context, `recurse=true`, `maxChildren=10`). The active scan is then aimed at the seed URL. A short noise list is disabled (`ZapNoiseRules`); SQLi, XSS, path traversal, and command-injection rules stay on. Alerts are stored as `ZAP_ALERT_<id>`. There is no authenticated context, no OpenAPI import, and no AJAX spider in the runner.

Individual Nuclei and ZAP ids can be turned off per org through the same override table as first-party rules, but they are not documented in the catalog until one of them has fired or been overridden.

## Comparison

"Yes" means the capability exists in a form a buyer would recognize. "Partial" means Bloodhound does a real version of it with a gap called out above. This is not a claim that the commercial product is better in every deployment. Several of those products are passive internet databases. Bloodhound actively talks to targets. Those are different promises.

| Capability | Bloodhound | Closest OSS | Typical paid EASM or scanner |
|---|---|---|---|
| Subdomain discovery | Partial. crt.sh, subfinder, and a katana crawl that reads hostnames out of the site's own JavaScript. No brute force, no permutation of the real name. The crawl is also finding 2. | amass, subfinder, puredns | Censys, Xpanse, Defender EASM, CyCognito attribute domains you did not seed |
| Cloud account inventory | No. No AWS, Azure, or GCP API connector. | cloudlist, Prowler (different job) | Defender EASM, Wiz, Prisma, Intruder cloud connectors |
| DNS email auth | Yes, and deeper than a bare SPF/DMARC presence check (lookup limit, dangling include, multiple SPF). | checkdmarc | Detectify, SecurityScorecard email factor |
| DNSSEC validation | Partial. DNSKEY presence only. | `delv`, dnsviz | Rarely a full validator in ASM products either |
| Zone transfer | Yes | dig, nuclei DNS templates | Common in vulnerability scanners, less central in rating products |
| Subdomain takeover | Partial. 14 CNAME services plus 4 NS providers, high-confidence fingerprints. | nuclei takeover templates, can-i-take-over-xyz (60-plus, including edge cases Bloodhound skips on purpose) | Detectify and similar maintain researcher-written checks and update them when a provider changes its error page |
| TLS quality | Partial. Expiry, chain, name, old protocols, a few weak suites, HSTS. | testssl.sh, sslyze, SSL Labs | Qualys SSL Labs grading is still the reference. Bloodhound is closer to a hygiene checklist than to that grade |
| CT monitoring | Partial. New certs for unknown names retrigger a scan. `TLS_CT_UNEXPECTED_ISSUER` does not read CT logs. | certspotter, crt.sh | Censys and Facebook/Cloudflare CT monitors are the real CT products |
| HTTP security headers | Yes, presence plus one CSP heuristic | Mozilla Observatory, securityheaders.com | Same checks, often with a published grade |
| Known-path exposure | Partial. A few dozen signatures, good false-positive discipline | nuclei `http/exposures` is far wider | Detectify and Intruder ship their own modules and retire them when they get noisy |
| Secret detection | Partial. Ten regexes, three URLs, redacted, not validated | gitleaks, trufflehog, nuclei token templates | GitHub secret scanning and similar validate some token types |
| CVE by version | Partial. Six product families, NVD, OSV, CISA KEV, endoflife.date | nuclei CVE templates (active confirmation, Tier 2 here) | Qualys, Tenable, Rapid7 correlate authenticated inventories. Version-from-a-banner is the weak form everywhere |
| Confirmed exploitable CVE | Partial, Tier 2 only, via Nuclei and ZAP, with OAST turned off so blind bugs are invisible | nuclei with Interactsh, ZAP, sqlmap | Detectify, Invicti, Burp Suite DAST. Authenticated scanning is the usual gap Bloodhound also has |
| Port exposure | Partial. 35 ports on Tier 1, full range on Tier 2, findings for a subset | naabu, masscan, zgrab2 (all three shapes exist in this repo already) | Censys and Shodan see the whole Internet's banners without connecting from your IP. Bloodhound's view is "from this worker" |
| Botnet / reputation | Partial. Feodo Tracker only | abuse.ch feeds | GreyNoise, Spamhaus, team Cymru |
| Brand lookalikes | Partial. 100 ASCII candidates, MX, live site, dHash | dnstwist | ZeroFox, Bolster, BrandShield add registrar feeds, dictionary names, IDN, and takedown workflow |
| Breach | Partial. HIBP domain, optional | HIBP itself | SpyCloud, Constella, and the commercial HIBP tiers go to identity level |
| Authenticated scanning | No | ZAP contexts, Burp | Detectify, Invicti, Intruder |
| API schema scanning | No, beyond noticing that Swagger or GraphQL introspection is exposed | ZAP OpenAPI, nuclei | Detectify API scanning, Burp |
| Attack-path graph of the customer's real network | No. The product graph is targets and subdomains, not an exploit path | — | Xpanse, CyCognito, and some CTEM suites sell this. Do not imply the Bloodhound map is that product |
| Outside-in vendor score (BitSight / SecurityScorecard style) | Partial. Own 0–100 score and a compare chart across targets you listed | — | Those scores mix leaked credentials, malware on employee endpoints, and patching cadence from Internet telemetry. Bloodhound only scores what it scanned |

### Where Bloodhound is genuinely ahead of a raw Nuclei or ZAP install

- The Tier 1 versus Tier 2 legal gate, with an attestation record, is not something you get from running nuclei in a shell.
- DNS checks (SPF lookup limit, dangling include, multiple SPF, lame NS, AXFR, MTA-STS fetch) are a coherent email-auth set. Stock Nuclei does not replace that.
- Exposure signatures are deliberately narrow. A stock Nuclei exposures run is wider and noisier.
- Compound rules are a small, explicit correlation layer. Most ASM products bury this in a risk score you cannot read.
- Per-org rule disable, including for `ZAP_ALERT_*` and `NUCLEI_*` once they exist, is the right operator control.
- Finding diff, dismiss/reopen, and the score time series are product features, not rule features, but they are why a rules gap is not the whole comparison.

### Where a buyer will notice the gap first

1. **You only know about names you can derive from the apex.** Commercial EASM's main claim is finding the subsidiary, the cloud account, and the IP range nobody seeded. Bloodhound does not do attribution.
2. **Tier 1 CVE coverage is a handful of banners.** The deep coverage is Nuclei, which is off unless the target is `OWN` and authorized, and which has the dial-pinning problem in finding 1. The Tier 1 crawl in finding 2 is a safety problem, not extra CVE coverage.
3. **Takeover and typosquat lists are intentionally small.** That is defensible for false positives. It is still less coverage than nuclei takeover templates or dnstwist with a dictionary and IDN.
4. **No authenticated or API-schema testing.** ZAP spidering an anonymous homepage misses the application.
5. **Several rules are noisier or weaker than their titles.** CSP `unsafe-inline` on styles, substring DMARC `p=none`, substring cookie flags, TCP-connect "open database" with no protocol banner, SSLv3 counted both as a weak protocol and as POODLE, and a "CT" rule that never consults a CT log.

---

# Part 3. Other improvements

Ordered by how much they change the product, not by how easy they are. None of this was implemented.

### Safety, before more rules

1. Take the worker's scan processes off `app_net`. Katana and Nuclei are the processes that matter. A scan network that does not contain `central-server` or `webui`, with job polling done by a small client that is the only thing on both networks, matches the threat. Until that split exists: tell katana not to request off-scope URLs (a scope flag that drops them before the fetch, not a filter on stdout), pass Nuclei a resolved public address or disable redirects, and exclude `javascript`, `code`, and `headless` tags. OAST stays off unless you run your own Interactsh. Clear the environment of those children so a crawler bug is not holding `WORKER_API_KEY`.
2. Make `ScanJobRepository.fail` include `claimed_by` and status in the `UPDATE`, the way `complete` already does. On revoke, and on a type change away from `OWN`, cancel queued Tier 2 jobs. `claim` should also refuse a deep-scan job whose target is no longer `AUTHORIZED`.
3. Issue a distinct worker credential per replica, bound to `workerId`, so a leaked key is one replica and the id cannot be chosen by the caller. Fail startup when `JWT_SIGNING_KEY` or `WORKER_API_KEY` is a known placeholder, unless an explicit dev flag is set. The banner is easy to miss on a forwarded port.
4. Do not let the screenshot browser share a network with ZAP. A one-way fetch network, or a browser with host firewall rules, matches the threat (the page is hostile).
5. Apply `HOSTNAME_PATTERN` to manually added subdomains. Do not treat an unresolvable string as safe when the next step is to paste it into a URL.
6. Stop copying Nuclei `extracted-results` and `curl-command`, and ZAP `evidence`, into the finding unchanged. Redact the same way the first-party secret rules do, or store a hash and a truncated preview.
7. On every SCIM transition to inactive, revoke that user's refresh tokens and API keys, and reject an API key whose creator is not `ACTIVE`. Do this before anyone links SAML login to SCIM rows. As the code stands, a SCIM user cannot open a session, so this is not the first fix.

### Rules and signal

8. Mark `NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED` as not a Tier 1 rule so it stops affecting the fair score.
9. Split the Nuclei corpus into a default profile (high and critical CVE, exposures, misconfigurations, known takeovers) and an optional full profile. Store the template id, severity, and CVE in a way the rules screen can show before the first hit.
10. Rebuild or refresh the template set on a schedule. It is copied into the image at build time and then frozen by `-disable-update-check`.
11. Extend takeover fingerprints from the high-confidence half of can-i-take-over-xyz, still requiring the provider's current unclaimed body, and add NS1-class DNS hosts only where an attacker can actually create the zone.
12. Typosquat: public-suffix split, a dictionary (`login`, `secure`, the brand plus those words), and Unicode homoglyphs with punycode. Keep the 100-candidate cap per technique rather than dropping the high-signal ones. Add dnstwist's "would this MX accept mail for us" only if you are willing to send a single RCPT probe and to document it as active.
13. Rename or replace `TLS_CT_UNEXPECTED_ISSUER`. Either consult a CT log, or call it an uncommon-issuer heuristic.
14. Parse DMARC tags instead of searching for `p=none`. Parse `Set-Cookie` attributes instead of searching the raw line. Stop treating `style-src 'unsafe-inline'` as the same finding as `script-src 'unsafe-inline'`.
15. For Tier 1 ports that are already connected (445, 2375, 9200, 22), either emit a finding or say in the UI that the port was seen and ignored. Silent open SMB is the one most likely to surprise an analyst.
16. Map WordPress plugin versions through the same NVD/KEV path, or explicitly say plugins are out of scope.
17. Add DANE/TLSA and OCSP stapling as low-severity TLS checks if the goal is testssl parity. Do not pretend the current TLS set is an SSL Labs grade.
18. A second reputation source next to Feodo, with the same "shared hosting" disclaimer. One feed is a thin `NETWORK_IP_KNOWN_BOTNET_C2`.
19. Cap AXFR by bytes, not only by record count. Give the ZAP spider a context that is the seed host. Compare document hosts on a public-suffix registrable domain, not on "either name is a suffix of the other." Put the 12/second limiter, or a lower one, in front of naabu, Nuclei, ZAP, and katana, shared across the three replicas.

### Product, not rules

20. The compare chart is only as fair as the Tier 1 rule set. Competitors and watchlist domains never receive Nuclei or ZAP, so a lower score on an `OWN` deep-scanned target can mean "we looked harder". Surface that in the compare view. The SSH-algorithm weight bug makes this worse.
21. Compound findings could be allowed to affect the score, at a small weight, or stay insight-only and be labeled that way in the UI. Right now a critical compound finding does not move the number analysts are comparing.
22. Audit log is append-only in the code that was read, which is good. It is not tamper-evident. A hash chain is the usual next step if the log is meant to survive a database admin.
23. MFA remains the main account-takeover gap. It was declined earlier. Password plus SSO is the whole login story until that changes.
24. Authenticated scanning and an OpenAPI upload would do more for application coverage than another fifty path signatures. They are also a large product, and they belong behind the same Tier 2 gate.
25. `cap_drop: ALL`, `no-new-privileges`, and a read-only root with a tmpfs for the scan scratch directory. None of that replaces the network split. It shortens what a scanner bug can do after it lands.

## Suggested order

1. Get Katana and Nuclei off the control-plane network. Until then, stop katana fetching off-scope URLs and stop Nuclei dialing a name it did not pin. Drop code-execution template tags.
2. Make `fail()` conditional on the lease, and cancel queued Tier 2 jobs when authorization is revoked or the target stops being `OWN`.
3. One worker credential per replica, and refuse to boot on a known placeholder secret.
4. Isolate the screenshot browser from ZAP. Reject subdomain strings that are not DNS names. Redact extracted secrets in Nuclei and ZAP evidence.
5. Fix the Tier 1 score so deep-only rules cannot move it. Say so in the compare UI.
6. Then widen takeover, typosquat, and the Nuclei default profile. More rules before items 1–3 mostly add findings from a scanner that can still be turned around at the platform.
7. SCIM revocation, before SAML is ever wired to SCIM users. It is not the current offboarding hole. The admin UI path already revokes.
