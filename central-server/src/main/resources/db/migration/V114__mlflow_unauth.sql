-- EXPOSURE_MLFLOW_UNAUTH: MLflow has no built-in authentication mechanism at all, the same
-- situation as the already-shipped EXPOSURE_PROMETHEUS_SERVER_UNAUTH - reachability of its own
-- tracking-server API is itself the finding, not a bypass of anything. Had no coverage at all
-- until now; increasingly common as "AI/data stack" EASM profiles grow more prevalent. Matched on
-- a real "experiments" response shape from /api/2.0/mlflow/experiments/list. HIGH, same tier as
-- EXPOSURE_PROMETHEUS_SERVER_UNAUTH - broad internal data/infrastructure disclosure, not direct
-- RCE.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_MLFLOW_UNAUTH', 'EXPOSURE', 'HIGH',
 'MLflow tracking server exposed without authentication',
 'An MLflow tracking server''s API on its default port (5000) is reachable, disclosing every experiment, run, metric, parameter, and model artifact path tracked on the server. MLflow has no built-in authentication mechanism at all, so reachability itself is the finding.',
 'Put an authenticating reverse proxy in front of the MLflow tracking server, or restrict access to trusted internal networks only.',
 1.3);
