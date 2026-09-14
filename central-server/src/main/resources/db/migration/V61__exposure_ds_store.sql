-- Added by the rules audit's new-rule pass. ExposedPathFetcher now probes /.DS_Store alongside its
-- existing exposure checks - macOS Finder's per-directory metadata file, accidentally deployed
-- whenever someone drags a folder onto a web server from a Mac without excluding it. See
-- ExposedPathDecisionLogic#looksLikeDsStore for the exact fixed-magic-string signature used to
-- confirm a match (never status-code-alone, matching every other probe in this module).
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_DS_STORE', 'EXPOSURE', 'MEDIUM',
 'Exposed .DS_Store file',
 'A macOS Finder .DS_Store file is publicly readable, disclosing the names of files and subfolders Finder has seen in this directory - including ones no longer present in the live listing - useful for reconnaissance of the site''s real directory structure.',
 'Remove the .DS_Store file from the deployed site and add it to .gitignore/deployment exclusions so it is never re-uploaded; configure the web server to deny access to dotfiles as a defense-in-depth measure.', 0.4);
