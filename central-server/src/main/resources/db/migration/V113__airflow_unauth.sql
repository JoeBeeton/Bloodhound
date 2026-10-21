-- EXPOSURE_AIRFLOW_UNAUTH: Airflow's webserver authentication has a real, documented history of
-- being disabled by default or left disabled after an upgrade (Airflow 1.x's own
-- authenticate=False default), or an anonymous/public role granted read access under the RBAC
-- model current Airflow uses. Had no coverage at all until now. Matched on a real DAG-list JSON
-- response ("dags" array) from the REST API; an authentication-requiring instance answers
-- 401/403 instead. CRITICAL: every DAG's own Python source is disclosed (often embedding
-- credentials or business logic), and depending on role configuration the same unauthenticated
-- access can extend to triggering DAG runs - arbitrary code execution on the Airflow host.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_AIRFLOW_UNAUTH', 'EXPOSURE', 'CRITICAL',
 'Apache Airflow exposed without authentication',
 'An Airflow webserver''s REST API answered a real DAG list without authentication, disclosing every DAG''s own Python source - which often embeds credentials or business logic - and, depending on the instance''s role configuration, may also allow triggering DAG runs, i.e. arbitrary code execution on the Airflow host.',
 'Enable Airflow''s authentication (RBAC) and ensure no anonymous/public role has been granted access, then restrict network access to the webserver to trusted hosts only.',
 1.0);
