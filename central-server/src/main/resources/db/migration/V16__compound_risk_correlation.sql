-- Compound-risk correlation (competitive-research-recommended: identified as
-- genuinely novel, since most commercial ASM tools present a flat findings
-- list with no correlation between findings that are individually modest but
-- materially worse together). CompoundRiskAnalysisService runs a curated,
-- bounded set of dangerous co-occurrence patterns over a target's currently-
-- open primary findings (grouped by affected_asset) after every scan_run
-- completes, and synthesizes a composite finding through the existing
-- findings table/ResultIngestionService pipeline under a synthetic
-- module_type of COMPOUND_ANALYSIS - no new findings table needed, this
-- reuses the existing one exactly like every real scan module already does.
--
-- COMPOUND is deliberately outside ScoringEngine's fixed 6-category weight
-- table, same precedent as WHOIS/BREACH/WEB_APP/BRAND: a compound finding is
-- a prioritization/insight layer describing risk that already exists in the
-- underlying findings' own categories - scoring it too would double-count
-- the same severity twice.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('COMPOUND_CREDENTIAL_TO_DATA_PIVOT', 'COMPOUND', 'CRITICAL',
 'Exposed credentials with a reachable path to data',
 'This host leaks live credentials or source (an exposed .env file, AWS credentials, or a full .git checkout) AND separately exposes an unauthenticated database or admin service on the same asset. Neither finding alone hands over data - together they are close to a complete credential-to-data pivot: an attacker does not need to guess or crack anything, just read the leaked secret and connect to the open service right next to it.',
 'Remediate both contributing findings, but treat the credential exposure as the higher priority: rotate any secrets that may have been leaked immediately, then remove the exposed file/service and restrict access to the data store to only the hosts that genuinely need it.',
 1.0),
('COMPOUND_CONTAINER_ESCAPE_AMPLIFICATION', 'COMPOUND', 'CRITICAL',
 'Exposed Docker API alongside another serious finding',
 'An unauthenticated Docker Engine API is already close to full host compromise on its own (it can create, run, and mount volumes into containers). A second Critical or High finding on the same asset means whatever that finding exposes - credentials, another service, a misconfiguration - can very plausibly be reached or escalated from inside a container the Docker API lets an attacker spin up.',
 'Restrict the Docker API to localhost/a private network immediately and require TLS client-certificate authentication for any remote access. Then remediate the second contributing finding, since it is now reachable via a much wider blast radius than it would be alone.',
 1.0),
('COMPOUND_INTERCEPTABLE_ADMIN_ACCESS', 'COMPOUND', 'HIGH',
 'Admin console reachable over weak or untrusted transport',
 'An exposed admin console (Jenkins script console, phpMyAdmin, or an unauthenticated Kibana) is bad enough on its own. On this asset it is also reachable over a connection that is not safely encrypted - a self-signed/untrusted certificate, a legacy TLS protocol still accepted, or no HSTS - meaning credentials typed into that console are at real risk of interception in transit, not just abuse once reached.',
 'Restrict access to the admin console (network-level allowlisting or authentication in front of it) and fix the TLS configuration on this host - a valid trusted certificate, modern protocol versions only, and HSTS enabled.',
 1.0),
('COMPOUND_ACTIVELY_EXPLOITED_EXPOSURE', 'COMPOUND', 'CRITICAL',
 'Actively-exploited software on an already-exposed host',
 'The fingerprinted software on this asset has a CVE confirmed by CISA''s Known Exploited Vulnerabilities catalog to be under active exploitation in the wild right now - not just theoretically vulnerable. Finding that on a host that also has a separate exposure/misconfiguration finding is the highest-confidence "this will actually get hit" signal Bloodhound can produce: real attackers are actively scanning for exactly this CVE.',
 'Patch the actively-exploited software immediately - this is the single highest-priority item this platform can surface. Then address the accompanying exposure finding on the same host.',
 1.0),
('COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE', 'COMPOUND', 'CRITICAL',
 'Full source checkout exposed alongside live credentials',
 'This asset exposes both a full .git checkout (enabling reconstruction of the entire source repository) and a live .env file with application secrets. Together that is close to a complete compromise kit handed directly to an attacker: the application''s own code to study, plus the credentials to run it against production.',
 'Remove both exposed paths immediately and rotate every credential that appeared in the .env file - treat them as already compromised, not merely at risk.',
 1.0);
