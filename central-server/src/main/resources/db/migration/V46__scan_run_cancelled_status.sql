-- CANCELLED was already a first-class terminal status for scan_jobs.status (see V3's own check
-- constraint) and was already handled everywhere in application code that reads scan_runs.status
-- (ScanEtaEstimator, ScanRunService#isTerminal, the Scans page's status filter/badge) - but
-- scan_runs.status's own check constraint was never widened to match, so there was never actually
-- a way to produce one: any attempt to mark a run CANCELLED failed with a check-constraint
-- violation. Found live, wiring up the new "Cancel scan" feature (RunController#cancel /
-- ScanRunService#cancel).
ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_status_check;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_status_check
    CHECK (status IN ('RUNNING', 'COMPLETE', 'PARTIAL_FAILURE', 'CANCELLED'));
