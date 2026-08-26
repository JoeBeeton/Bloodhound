INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_LIVE_SECRET_DETECTED', 'EXPOSURE', 'CRITICAL',
 'Live-looking secret found in exposed file',
 'The contents of an already-exposed file (.env, .git/config, or AWS credentials) contain one or more strings matching known live-credential formats (AWS access keys, private key blocks, Slack/GitHub/Stripe tokens, credential-embedded URLs, or other generic high-entropy secret assignments) - confirming the exposed file carries working-looking secrets, not just configuration structure.',
 'Rotate every credential found in the exposed file immediately, then remove the file from the public web root (or restrict access to it) - rotation matters even after removal, since the file may already be cached or scraped.',
 2.0);
