-- Worker presence tracking, populated as a side effect of the existing /jobs/claim
-- poll (which every worker already calls on a fixed interval regardless of whether
-- a job is actually available) - no new worker-side network call needed.
CREATE TABLE workers (
    worker_id text PRIMARY KEY,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_heartbeat_at timestamptz NOT NULL DEFAULT now(),
    -- Nullable: set when the worker claims a job, cleared when that job reaches a
    -- terminal state (or is reaped). One column, not a list, because worker capacity
    -- is 1 (sequential per-worker processing, see JobPollingLoop's own doc comment) -
    -- this would need revisiting if capacity is ever raised above 1.
    current_job_id uuid REFERENCES scan_jobs(id)
);
