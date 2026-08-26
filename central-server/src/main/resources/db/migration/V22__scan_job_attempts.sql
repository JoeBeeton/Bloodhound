-- Full per-attempt retry history for a scan_job. scan_jobs.error_detail/attempt_count
-- are overwritten on every retry, so a job that failed 3 times with 3 different errors
-- before landing in FAILED only ever exposed the *last* one - this table keeps the
-- complete timeline (each attempt's worker, timing, and specific outcome/error) for
-- the scan-detail page's failure drill-down. Purely additive: scan_jobs' own columns
-- and behavior are unchanged, this is a parallel log, not a replacement.
CREATE TABLE scan_job_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    attempt_number int NOT NULL,
    claimed_by text NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    outcome text CHECK (outcome IS NULL OR outcome IN ('SUCCESS', 'FAILED', 'TIMED_OUT_REAPED')),
    error_detail text
);

CREATE INDEX idx_scan_job_attempts_job ON scan_job_attempts (scan_job_id, attempt_number);
