-- A security review found EXPOSURE_CHECKS (ExposedPathFetcher) was never
-- actually passive, despite running unconditionally as a Tier 1 module
-- against every target including unauthorized COMPETITOR/WATCHLIST ones: it
-- attempts a RabbitMQ guest:guest login, POSTs an etcd "dump every key"
-- range request, probes JDWP/Redis/VNC, and fetches credential-shaped paths
-- (/.aws/credentials, /id_rsa, /actuator/heapdump, Kubernetes/Docker/Jenkins
-- control APIs) - materially different from the genuinely passive checks
-- Tier 1 is supposed to be limited to. ScanRunService now gates
-- EXPOSURE_CHECKS the same way PORT_SCAN_DEEP/ZAP_ACTIVE_SCAN/NUCLEI_SCAN
-- already are: OWN + AUTHORIZED targets only, via a deep scan.
--
-- Every rule this module emits can therefore no longer fire from a Tier 1
-- run, so emitted_by_tier1 is flipped to false to keep the "fair"
-- (Tier-1-only) Compare score honest - excludes the two EXPOSURE_DOCUMENT_METADATA_*
-- rules (DOCUMENT_METADATA module, unaffected, stays Tier 1) and
-- EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC (BUCKET_BRUTE_FORCE, already Tier 2 /
-- already false).
UPDATE rules_catalog
SET emitted_by_tier1 = false
WHERE rule_id LIKE 'EXPOSURE_%'
  AND rule_id NOT IN (
    'EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO',
    'EXPOSURE_DOCUMENT_METADATA_PATH_LEAK',
    'EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC'
  );
