-- EXPOSURE_SVN_ENTRIES: Subversion's own equivalent of the already-shipped EXPOSURE_GIT_CONFIG -
-- a standard pairing in most scanners (Nikto checks both .git/config and .svn/entries). Pre-1.7
-- SVN working copies keep a plain-text entries file per directory disclosing the full repository
-- URL and revision metadata, often enabling source reconstruction - the same risk
-- EXPOSURE_GIT_CONFIG covers for Git. Matched on the format-version line (a bare integer) followed
-- by a "dir" marker on its own line - distinctive enough to avoid matching an arbitrary
-- numbers-containing text file. Only catches older (pre-1.7) working copies, which use this
-- plain-text format rather than the SQLite-based .svn/wc.db later versions switched to - still a
-- real, if shrinking, population given how long unmaintained legacy deployments stay online.
-- CRITICAL, same tier as EXPOSURE_GIT_CONFIG.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_SVN_ENTRIES', 'EXPOSURE', 'CRITICAL',
 'Exposed .svn/entries',
 'A Subversion working copy''s .svn/entries file is publicly readable, disclosing the full repository URL and revision metadata and often enabling source reconstruction, the same risk EXPOSURE_GIT_CONFIG covers for Git.',
 'Remove the .svn directory from the publicly served web root, or explicitly block access to paths starting with .svn at the web server or reverse proxy.',
 1.0);
