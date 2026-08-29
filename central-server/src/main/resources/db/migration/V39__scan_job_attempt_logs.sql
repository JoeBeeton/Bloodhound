-- Captured worker log output for a scan_job_attempt - see JobLogCapture (worker) for how this
-- is gathered: a thread-local buffer fed by a Logback appender, active only while a job is
-- actually executing on the worker's polling thread, capped at 500 lines. Closes a real
-- diagnosability gap found live investigating a ZAP failure flood: error_detail alone (a terse
-- wrapper message) gave no way to see what actually happened during execution without shelling
-- into the worker container. Stored as plain newline-joined TEXT, not JSONB - this is rendered
-- as a single scrollable log block in the UI, never queried/filtered by individual line.
ALTER TABLE scan_job_attempts ADD COLUMN log_output TEXT;
