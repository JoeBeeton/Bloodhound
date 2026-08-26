-- Milestone 5: the scoring engine's persisted output. One row per completed
-- scan_run, computed from that target's currently-OPEN findings at the
-- moment the run finished. Append-only - never updated or deleted, since
-- this is the time series the trend chart and compare view read from.
CREATE TABLE score_snapshots (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id         UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_run_id       UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    computed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    overall_score     NUMERIC(5, 2) NOT NULL,
    grade             CHAR(1) NOT NULL CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
    category_scores   JSONB NOT NULL,
    finding_counts    JSONB NOT NULL
);

-- The query both /score/history and the "latest score per target" lookup run.
CREATE INDEX idx_score_snapshots_target_computed ON score_snapshots(target_id, computed_at DESC);
