-- Added by the rules audit's new-rule pass. ExposedPathFetcher now probes a curated set of
-- commonly-exposed directory names (/backup/, /uploads/, /logs/, etc. - real directory names on
-- an arbitrary target can't be known in advance, same "probe common guesses" approach
-- EXPOSURE_PHPMYADMIN/EXPOSURE_GIT_CONFIG already take) for Apache/nginx autoindex output. See
-- ExposedPathDecisionLogic#looksLikeDirectoryListing for the "Index of /" signature, captured
-- live against a real nginx autoindex response added specifically to verify this against genuine
-- output rather than a guessed format.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_DIRECTORY_LISTING', 'EXPOSURE', 'MEDIUM',
 'Directory listing enabled',
 'A web server directory listing (Apache/nginx autoindex) is publicly reachable on a commonly exposed path, disclosing the names of every file it contains - including backups, logs, or uploads that were never meant to be individually discoverable.',
 'Disable directory autoindexing for this path (Apache: "Options -Indexes"; nginx: "autoindex off;", the default) and add an index file or explicit access control if the directory must remain reachable.', 0.4);
