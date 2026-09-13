-- SUBDOMAIN_STALE_NOT_RESOLVING ("previously tracked, no longer resolves") fired for any known
-- hostname that didn't resolve this run - including the tens of thousands of certificate-
-- transparency artifacts that never resolved in the first place. Live data: github.com had
-- 41,268 OPEN "no longer resolving" findings against 41,698 tracked subdomains of which 430
-- have ever answered DNS. "No longer" needs a "was": last_resolved_at records the most recent
-- run in which this hostname actually resolved, and the rule now requires it.
--
-- Backfill is best-effort: a currently-active row resolved on its last run, so it gets that
-- timestamp; an inactive row's history is unknowable from here and stays NULL, which means no
-- stale finding for it until it resolves again - the safe direction.
ALTER TABLE subdomains ADD COLUMN last_resolved_at timestamptz;
UPDATE subdomains SET last_resolved_at = last_seen_at WHERE is_active;
