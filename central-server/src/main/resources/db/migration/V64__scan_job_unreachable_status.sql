-- A scan module confirming a host is genuinely unreachable (DNS resolution failure) is a
-- correct scan outcome, not a bug - but scan_jobs.status only had FAILED as a terminal
-- "gave up" outcome, so a confirmed-dead host was indistinguishable from a real failure
-- (a timeout, a crash, a bad response) and dragged the whole scan run to PARTIAL_FAILURE.
-- Widens the status check constraint to add UNREACHABLE, a terminal status that
-- ScanRunService#checkAndCompleteRun treats as terminal but not as a failure. Same
-- DROP+ADD CONSTRAINT pattern as V46__scan_run_cancelled_status.sql.
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_status_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('PENDING', 'CLAIMED', 'RUNNING', 'COMPLETE', 'FAILED', 'CANCELLED', 'UNREACHABLE'));
