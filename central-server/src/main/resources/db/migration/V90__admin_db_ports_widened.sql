-- Widened PORT_UNEXPECTED_OPEN_ADMIN_SERVICE's own port coverage in PortScanDecisionLogic to
-- include three more scanned-but-previously-unclassified ports: 27018 (MongoDB's shard-server
-- default port - the same unauthenticated-database risk as the already-covered 27017), 9300
-- (Elasticsearch's own internal transport protocol - a separate attack surface from the REST API
-- on 9200, with its own RCE history), and 9092 (a raw Kafka broker - historically shipped with no
-- built-in authentication at all). Description-text update only, no new rule_id - same pattern as
-- V71's bucket-bruteforce remediation-text update.
UPDATE rules_catalog
SET description = 'A port commonly used by a database or remote-administration service (e.g. RDP, MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle, VNC, CouchDB, Elasticsearch, Kafka) was found open and reachable.'
WHERE rule_id = 'PORT_UNEXPECTED_OPEN_ADMIN_SERVICE';
