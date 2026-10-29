-- New rule for the GITHUB_SECRET_SEARCH module: a two-stage check (GitHub code search for the
-- target's own domain, then a local re-check of any hit with the existing SecretPatternScanner,
-- the same matcher already used for .env/.git/config/JS-bundle findings) finds a live-looking
-- secret in a PUBLIC repository, not on the target's own infrastructure at all - a distinct leak
-- vector competitors (e.g. UpGuard) explicitly market and this catalog had zero coverage for.
-- Separate rule_id from EXPOSURE_LIVE_SECRET_DETECTED since the evidence shape is different
-- (repo name, file path, GitHub URL vs. an on-host fileLabel).
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_SECRET_IN_PUBLIC_REPO', 'EXPOSURE', 'CRITICAL',
 'Live-looking secret found in a public code repository',
 'A public GitHub repository mentioning this domain contains a string matching a known live-credential format (AWS key, private key, API token, etc.). Unlike a secret found on the target''s own infrastructure, this one is already indexed and scraped by search engines and automated credential-harvesting bots the moment it''s pushed.',
 'Rotate/revoke the credential immediately, then remove it from the repository''s history (a simple follow-up commit deleting the line is not enough - use git-filter-repo or BFG Repo-Cleaner to purge it from every commit, and force-push). Add the file pattern to .gitignore and verify no other files in the repo carry secrets.', 1.0);
