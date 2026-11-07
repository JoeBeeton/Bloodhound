# Bloodhound security review

Read-only review of the current tree, oriented by `ctx.md` and focused on security. No code was changed as part of this review.

Overall: this codebase has already been through several hardening passes (SSRF guard, refresh-token rotation, DCR consent, MCP disable checks, network segmentation, non-root containers, rate limiters). The remaining issues are not “nothing was thought about.” They are control-plane gaps that sit next to those fixes — several of them still look exploitable.

Every item below is from the current source, including tests and comments that already describe the behavior. The stack was not exploited live as part of this review.

---

## Highest-priority findings

### 1. Job results are ingested before the worker lease is checked

**Severity:** High

**Files:** `central-server/src/main/java/org/freedonia/bloodhound/server/jobqueue/JobLifecycleService.java:88-148`, `ScanJobRepository.java:188-196`

**Evidence:** `JobLifecycleServiceTest.java:178-185` is named `result_completeFails_stillThrows404_evenThoughIngestionAlreadyHappened`.

`POST /api/v1/jobs/{id}/result` does this:

1. `findById(jobId)` — any job, any status, any worker
2. Ingest findings / subdomains / fingerprints against that job’s `targetId`
3. Then `complete(jobId, workerId)`, which is the first `claimed_by` + `CLAIMED|RUNNING` check

`FindingReconciler` treats “not in this batch” as resolved. An empty or forged `findings` list can **close real findings**, not only insert fake ones.

`WORKER_API_KEY` is one shared fleet secret. `workerId` is client-supplied and not bound to the credential. Anyone who has the key can:

- Claim any org’s jobs
- Or skip claiming and POST results for a known job UUID (scan-run UI, logs, MCP `get_scan_run`)

**Fix:** Authorize first (`claimed_by = workerId AND status IN ('CLAIMED','RUNNING')`, `SELECT … FOR UPDATE`), ingest, then complete, in one transaction. Bind `workerId` to the authenticated credential.

---

### 2. Any org ADMIN can disable findings for every tenant

**Severity:** High (if you ever have more than one org)

**File:** `central-server/src/main/java/org/freedonia/bloodhound/server/rulescatalog/RulesCatalogController.java:54-75`

`PATCH /api/v1/rules-catalog/{ruleId}` updates the global `rules_catalog` table. There is no `organization_id`. The comments already admit the effect is global. `ResultIngestionService` then drops those rule IDs for **every** org’s next scan, and open findings for that rule resolve themselves.

Tenant A’s admin can turn off `TLS_EXPIRED` (or worse) for tenant B.

**Fix:** Per-org overlay table. Ingestion must filter by the job’s org, not a shared `enabled` flag.

---

### 3. MCP `/login/**` captures the SAML ACS

**Severity:** High (auth control plane)

**Files:** `McpSecurityConfig.java:62-70` (`@Order(-10)`), `SecurityConfig.java:86-96` (`@Order(1)`), `DbRelyingPartyRegistrationRepository.java:62`

MCP matcher includes `/login` **and** `/login/**`. Spring uses the first matching filter chain. ACS is `/login/saml2/sso/{slug}`.

That means IdP POSTs of `SAMLResponse` hit the MCP chain (formLogin + CSRF), not `saml2Login`. The SAML assertion is never validated on the path you think it is. Typical result: CSRF 403 and SSO silently broken. `/login/**` is unnecessary for `?error` (query string is not a path).

**Fix:** Match exact `/login` only. Confirm with an integration test that ACS is handled by the SAML chain.

---

### 4. Disabling a user does not revoke their API keys

**Severity:** High (offboarding)

**Files:** `OrgUserController.java:133-177`, `ApiKeyAuthFilter.java:65-82`

Refresh is correctly rejected for `DISABLED` (`AuthenticationService.java:100-103`). API keys are not. `ApiKey.isActive()` only checks expiry/revocation. Keys default to 90 days. Any `ADMIN`/`ANALYST`/`VIEWER` can mint one.

Offboarded (or compromised-then-disabled) users keep read access to that org’s targets, findings, and scans.

Password reset *does* revoke refresh tokens. Disable does not revoke keys or remaining sessions (sessions fail on next refresh via the `ACTIVE` check; keys do not).

**Fix:** On `DISABLED`, revoke API keys for `created_by_user_id`. In the filter, require the creating user to still be `ACTIVE`.

---

### 5. Tier 2 is not restricted to `OWN` targets

**Severity:** High (legal / product-safety model)

**Files:** `TargetAuthorizationController.java:53-76`, `TargetController.java:359-368`, `webui/frontend/src/pages/TargetsPage.tsx:808-811`, `TargetDetailPage.tsx:615-619`

README and UI treat Tier 2 as “only against infrastructure you attested you may attack.” The list page hides Deep scan for `COMPETITOR`/`WATCHLIST`. The API does not check `targetType`. Authorization panel is on every target detail page.

An ANALYST can:

1. Add `competitor.com` as `COMPETITOR`
2. `POST /authorization` with any attestation text
3. `POST /scan/deep`

That queues nuclei, naabu, zgrab2, ZAP against a third party. You can also authorize as `OWN`, then `PATCH` the type to `COMPETITOR`.

**Fix:** Server-side: only `OWN` targets may be authorized or deep-scanned. Changing type away from `OWN` must revoke authorization.

---

### 6. Nuclei talks to ProjectDiscovery Interactsh by default

**Severity:** High (data leak on authorized deep scans)

**File:** `worker/src/main/java/org/freedonia/bloodhound/worker/modules/nuclei/NucleiFetcher.java:97-114`

Nuclei 3.11.1, full template corpus, no `-no-interactsh` / `-ni`.

OAST templates inject `{{interactsh-url}}` and poll `oast.pro` / `oast.fun` / etc. That sends customer hostnames, IPs, and scan callbacks to a third party. Nuclei also re-resolves and follows redirects for up to 20 minutes after a single `requireSafeIfResolvable` check, while the worker sits on `app_net` with central-server — so DNS rebinding / 302-to-internal is in the same path.

**Fix:** Pass `-no-interactsh` (or a self-hosted Interactsh). Re-check / pin the scan IP during the run. Do not let nuclei follow redirects onto Docker/RFC1918 space.

---

## Medium

### 7. SAML handoff stores live refresh tokens in plaintext

**File:** `SsoHandoffCodeRepository.java:39-51`

The main `refresh_tokens` table stores SHA-256 hashes. SSO success writes the **raw** access and refresh tokens into `sso_handoff_codes`. Consume is `DELETE … WHERE expires_at > now()`, so expired unused rows are never deleted. A closed-tab SSO attempt leaves a 30–90 day refresh token sitting in that table for anyone with DB/backup access.

**Fix:** Mint tokens only at exchange time, or store a handle/hash. Sweep expired rows.

---

### 8. Session JWT is not re-checked against live user state

**File:** `JwtAuthenticationFilter.java:38-47`

Role, org, and user id are trusted from the token for 15 minutes. MCP already re-checks `ACTIVE` + kill switches on every tool call (`McpEnabledGuardFilter`). Disable/demote does not kill an existing access token. Stolen access tokens work until expiry.

**Fix:** Same live check as MCP, or a jti denylist. On disable, revoke refresh **and** keys.

---

### 9. Unauthenticated DCR is still consent phishing

**Files:** `McpSecurityConfig.java:71-84`, `McpLoginConsentPageController.java:143-214`

Consent is required (good). XSS on `client_name` is escaped (good). An attacker can still `POST /oauth2/register` (5/hour/IP), name the client `"Claude Desktop"`, and send a user an authorize link. The consent page does not show `redirect_uri`. Authorize sends the code to the attacker.

**Fix:** Show `redirect_uri` and that the client is self-registered. Force PKCE (`requireProofKey(true)`). Consider restricting redirect URI schemes.

---

### 10. DNS modules skip the SSRF guard

**Files:** `DnsZoneFetcher.java:78-90, 101-114, 167-174`; `DnsRecordFetcher.java:76-77, 101-112`

- AXFR/SOA connects to attacker-controlled NS IPs with no `SafeAddressValidator`. `NsTakeoverChecker` already drops unsafe NS addresses; this path does not. Result: TCP/53 to RFC1918 / link-local (port-53 oracle, not IMDS dump).
- MTA-STS does `GET https://mta-sts.{target}/.well-known/mta-sts.txt` on a plain `HttpClient` with no SSRF check. Derived hostname is not the apex checked at target create. Result: 443 reachability oracle to private space.

**Fix:** Same `isUnsafeToConnect` / `SafeHttpGet` as every other outbound path.

---

### 11. Document fetches are not same-origin

**File:** `DocumentLinkDecisionLogic.java:50-55`

Any `http(s)` PDF/Office link on the homepage is downloaded (up to 5, 20MB) and parsed with PDFBox/POI. Tests expect off-origin CDNs. Fetch is SSRF-gated, so this is not internal SSRF. It is an untrusted-document parser on the shared worker (2G cgroup), plus a bounded open fetch of third-party URLs.

**Fix:** Same-site or same-eTLD+1 restriction; set POI zip-secure limits; time-budget PDF parsing.

---

### 12. WebUI proxies `/api/v1/auth/**`

**File:** `webui/backend/src/main/java/org/freedonia/bloodhound/webui/proxy/ApiProxyController.java:53-71`

The SPA correctly uses `/api/auth` (httpOnly `bh_refresh`). The transparent proxy still forwards `/api/v1/auth/login` and `/refresh` on the browser origin, and Swagger is proxied `permitAll`. “Try it out” on login returns the raw refresh token in JSON, outside the cookie design.

**Fix:** Exclude `/api/v1/auth/**` from `ApiProxyController`.

---

### 13. IPv4-compatible IPv6 can skip RFC1918 checks

**File:** `bloodhound-common/src/main/java/org/freedonia/bloodhound/common/net/SafeAddressValidator.java:62-100`

`::ffff:10.0.0.1` is tested and blocked (JDK normalizes to IPv4). `::10.0.0.1` is an `Inet6Address`; the IPv4 private-range checks never run. Exploitability is OS/stack dependent (IPv4-compatible is deprecated). Worth closing.

**Fix:** If IPv4-compatible/mapped, unwrap the last 4 bytes and recurse. Consider rejecting NAT64 `64:ff9b::/96`.

---

### 14. Worker result payloads are unbounded

**File:** `JobResultRequest.java:8-12`

No `@Size` on `findings`, `evidence`, or `logLines`. Combined with finding 1, a stolen worker key can write arbitrary JSONB into Postgres.

**Fix:** Cap list length, evidence JSON size, and log lines at the DTO.

---

## Lower / residual

| Item | Notes |
|---|---|
| Shared `WORKER_API_KEY` | By design for a trusted fleet; it is still a cross-tenant write primitive. Treat like a root scanning credential. Fail closed on placeholders. |
| ZAP API key on cmdline | Documented; juice-shop on `targets_net` can TCP to ZAP. Key is the remaining control. |
| JWT/worker placeholder warn-only | `JwtService` / `WorkerCredentialBootstrapRunner` log and continue. Forging HS256 session JWTs is trivial if `.env` is still the example value. |
| Public org-slug oracle | `GET /api/v1/public/sso/{slug}` → 404 vs `{enabled, url}`. |
| SCIM `count` uncapped | Clamp like other list endpoints. |
| SAML JIT email/displayName uncapped | SCIM and admin-create have 320/200 caps; SAML does not. |
| Email uniqueness is case-sensitive | Lockout key is lowercased; login match is not. |
| Login limiter is per-email, in-memory | Credential stuffing many accounts at 9 guesses each is allowed. Documented single-instance gap. |
| Access token lives 15 min after logout | Normal for stateless JWT. |
| HttpClient DNS-rebinding TOCTOU | Documented in `SafeHttpGet`. Closed for Redis/TLS via `resolveSafeAddress`. Still open for nuclei/ZAP/Chromium. |
| MCP signing key ephemeral | Restart drops MCP sessions (availability). |
| Central-server `:8080` published | MCP/DCR/Swagger live here. Fine for local; don’t ship that in prod. |
| Bootstrap password not weak-checked | Only self-service change uses `WeakPasswordChecker`. |
| Consent Cancel `onclick` vs `script-src 'none'` | Dead button, not XSS. |

---

## What already looks solid

These were checked and would **not** be filed:

- JWT `alg=none` / algorithm confusion (jjwt `verifyWith` HMAC)
- Refresh rotation, reuse detection, absolute 90-day cap, `tryRevoke` race
- Refresh tokens hashed at rest (except the SSO handoff table)
- API/SCIM/worker keys stored as SHA-256
- BCrypt cost 12
- Login error text does not enumerate users
- SCIM filter is a regex + bound parameter, always `VIEWER`, org-scoped
- SAML ACS URL from config, not `Host`; JIT role is `VIEWER`
- Slack webhook host parsed via `URI.getHost()`, not prefix match
- Org IDOR on targets/findings/compare/diff/audit/MCP connections (UUID lookups go through `findByIdAndOrganization` / `requireSameOrg`)
- MCP tool org-scoping from token claims; disabled-user refresh cannot call tools
- DCR `client_name` HTML-escaped; CSP on login/consent
- No `dangerouslySetInnerHTML` in the SPA; access token is memory-only
- CSV formula injection guarded (`=`, `+`, `-`, `@`)
- Subprocess calls are `ProcessBuilder` lists, not a shell; nuclei rejects leading `-`
- Postgres unpublished; `db_net` internal; juice-shop on `dev-fixtures`; app images `USER 1000:1000`
- Actuator limited to health, `show-details: never`

---

## Suggested order of work

1. **Lease-then-ingest** on worker results (finding 1) — this is a live write primitive.
2. **MCP matcher vs SAML ACS** (finding 3) — confirm whether SSO actually works today.
3. **Per-org rules catalog** (finding 2).
4. **Revoke API keys on disable** (finding 4).
5. **Enforce `OWN` for Tier 2** (finding 5).
6. **`-no-interactsh` (or self-hosted) + nuclei redirect/rebind controls** (finding 6).
7. Then the medium list: handoff tokens, DNS SSRF, DCR phishing UX, document same-origin, auth proxy exclusion.
