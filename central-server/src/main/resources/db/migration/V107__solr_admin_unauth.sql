-- EXPOSURE_SOLR_ADMIN_UNAUTH: Apache Solr has no built-in authentication enabled by default - its
-- admin API is reachable on its default port (8983) with no credentials whatsoever unless an
-- operator explicitly layers on Basic Auth/Kerberos or a reverse proxy. Solr's own history
-- includes multiple RCE-class CVEs reachable once any admin API access is available (e.g.
-- CVE-2017-12629 XXE+RCE via the Config API, CVE-2019-0193 RCE via the DataImportHandler), making
-- bare unauthenticated admin access itself the meaningful finding, independent of any one specific
-- CVE. Had no coverage at all until now. Matched on /admin/info/system's real response shape (both
-- a "solr_home" path and a "lucene" object) - a hardened install behind an auth-requiring reverse
-- proxy returns a 401/403 challenge instead. CRITICAL, same tier as this product's other
-- unauthenticated-admin-API findings (Docker, Kubernetes, etcd).
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_SOLR_ADMIN_UNAUTH', 'EXPOSURE', 'CRITICAL',
 'Apache Solr admin API exposed without authentication',
 'The Apache Solr admin API is reachable on its default port (8983) without authentication. Solr has no built-in authentication enabled by default, and its history includes multiple RCE-class CVEs reachable once any admin API access is available (e.g. CVE-2017-12629 XXE+RCE via the Config API, CVE-2019-0193 RCE via the DataImportHandler) - bare unauthenticated admin access is itself the meaningful finding, independent of any one specific CVE.',
 'Enable Solr''s Basic Authentication or Kerberos plugin, or restrict network access to the admin port to trusted hosts only. Upgrade to a current Solr release to close any version-specific RCE vectors.',
 1.0);
