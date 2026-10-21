-- EXPOSURE_ETCD_UNAUTH: etcd's v3 gRPC-gateway KV API on its default client port (2379), left
-- entirely absent from this product's rule set until now. etcd backs Kubernetes' entire cluster
-- state - including Secrets, which (absent an explicit encryption-at-rest configuration) are
-- stored base64-encoded rather than truly encrypted - so an unauthenticated, queryable etcd is
-- close to full cluster compromise, not just a data-disclosure finding, on par with
-- EXPOSURE_ELASTICSEARCH_UNAUTH's own tier. Confirmed via an actual KV range query for the entire
-- keyspace (key=range_end=0x00, etcd's own documented "every key" convention), not just a bare
-- open-port check - matched on etcd's own gRPC-gateway response envelope ("header"/"cluster_id",
-- the latter rendered as a JSON string per etcd's int64-as-string encoding quirk), which an
-- auth-rejecting response would not carry. CRITICAL.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_ETCD_UNAUTH', 'EXPOSURE', 'CRITICAL',
 'etcd exposed without authentication',
 'An etcd instance''s v3 KV API is reachable on its default port (2379) without authentication, allowing a full read of every key in the store. etcd commonly backs Kubernetes'' entire cluster state, including Secrets, which (absent an explicit encryption-at-rest configuration) are stored base64-encoded rather than truly encrypted - making an exposed, unauthenticated etcd close to a full cluster compromise, not just a data-disclosure finding.',
 'Enable etcd client-certificate authentication (--client-cert-auth) and restrict network access to the cluster''s own control-plane nodes only. Never expose etcd''s client port to the internet.',
 1.0);
