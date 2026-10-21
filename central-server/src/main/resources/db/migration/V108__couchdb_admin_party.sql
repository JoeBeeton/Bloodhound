-- EXPOSURE_COUCHDB_ADMIN_PARTY: CouchDB's historical "admin party" mode (no admin user
-- configured at all - the pre-2.0 default, still reachable on any instance that skipped the setup
-- wizard): anyone can read (and in true admin-party mode, write) any database with no
-- authentication whatsoever. Distinct from the existing generic PORT_UNEXPECTED_OPEN_ADMIN_SERVICE
-- classification (port 5984 open) - this is an actual confirmation of unauthenticated data access,
-- the same kind of upgrade EXPOSURE_REDIS_UNAUTH/EXPOSURE_ELASTICSEARCH_UNAUTH already represent
-- over a bare port-open check. Matched on a real unauthenticated /_all_dbs response: a JSON ARRAY
-- containing the literal "_users" system database name (present on every CouchDB install, modern
-- or old) - a hardened (post-2.0, admin-user-configured) instance instead returns a JSON OBJECT
-- error. CRITICAL.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_COUCHDB_ADMIN_PARTY', 'EXPOSURE', 'CRITICAL',
 'CouchDB reachable with no admin user configured ("admin party")',
 'A CouchDB instance answered /_all_dbs without authentication, listing every database on the server. This is CouchDB''s historical "admin party" mode (no admin user configured at all, the pre-2.0 default) - with no admin user set, read and write access to every database is open to anyone who connects.',
 'Create an admin user immediately (CouchDB''s setup wizard or the _node config API), which disables admin-party mode and requires authentication for all database access.',
 1.0);
