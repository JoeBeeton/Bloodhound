-- A rules audit against live data found that every Tier 2 finding (NUCLEI_SCAN, ZAP_ACTIVE_SCAN,
-- PORT_SCAN_DEEP) was being "resolved" within minutes of being opened - 92% of all RESOLVED rows
-- for those modules, resolved inside 30 minutes, with the same (rule, asset) re-opened on every
-- deep scan since (7 identical rows for one nuclei deprecated-tls hit, 670 for one ZAP alert).
-- Cause: ScanRunService#createDeepScan dispatches one scan_jobs row per (module, host) so the
-- work spreads across workers, but ResultIngestionService reconciled each job's results against
-- ALL open findings for (target, module) - so host A's job, which naturally reports nothing about
-- host B, resolved every one of host B's findings, and host B's job re-opened them minutes later.
--
-- scan_scope records which host a per-host job was responsible for; reconciliation now only
-- resolves open findings within the same scope (NULL for whole-target modules, unchanged
-- behaviour). Backfilled from the job payloads so existing Tier 2 findings don't flap one more
-- time on the first post-upgrade scan: a finding's scope is the host among its run's per-host
-- jobs (same module) whose name appears in the affected asset - longest host wins, so
-- "seedrs.jaja.co.uk" assets go to that host's job rather than the root "jaja.co.uk" job.
ALTER TABLE findings ADD COLUMN scan_scope text;

UPDATE findings f
SET scan_scope = best.host
FROM (
    SELECT DISTINCT ON (f2.id) f2.id, j.host
    FROM findings f2
    JOIN (
        SELECT DISTINCT scan_run_id, module_type, payload->>'host' AS host
        FROM scan_jobs
        WHERE payload ? 'host'
    ) j ON j.scan_run_id = f2.scan_run_id AND j.module_type = f2.module_type
    WHERE f2.affected_asset = j.host OR f2.affected_asset LIKE '%' || j.host || '%'
    ORDER BY f2.id, length(j.host) DESC
) best
WHERE f.id = best.id;

-- findOpenKeys filters on (target_id, module_type, status, scan_scope); the existing
-- idx_findings_target_status covers the selective prefix, and OPEN rows per target are
-- small enough that a dedicated index on scan_scope isn't warranted.
