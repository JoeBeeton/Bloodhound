-- EXPOSURE_JUPYTER_UNAUTH: Jupyter requires its token/password for every API endpoint by default,
-- except on an install explicitly started with --NotebookApp.token='' and
-- --NotebookApp.password='' - a real, documented "just let me use it locally" convenience
-- sometimes left in place on a publicly reachable host. Had no coverage at all until now. Matched
-- on a real, unauthenticated /api/status response shape; a protected instance answers 403
-- instead. CRITICAL: notebook cells execute arbitrary code, so unauthenticated access is
-- equivalent to direct remote code execution on the host.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_JUPYTER_UNAUTH', 'EXPOSURE', 'CRITICAL',
 'Jupyter Notebook exposed without authentication',
 'A Jupyter Notebook instance on its default port (8888) answered its API without requiring a token or password, confirmed via a real /api/status response. Jupyter''s notebook cells execute arbitrary code - unauthenticated access is equivalent to direct remote code execution on the host.',
 'Set a token or password immediately (Jupyter generates one by default; never run with --NotebookApp.token='''' or --NotebookApp.password='''' on a publicly reachable host), and restrict network access to trusted hosts only.',
 1.0);
