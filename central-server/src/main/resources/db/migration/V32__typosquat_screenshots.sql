-- Visual-similarity check for typosquat candidates (worker.TyposquatChecker):
-- a screenshot of each genuinely-registered lookalike's homepage, compared
-- via perceptual hash against the real target's own homepage. Kept as bytea
-- in Postgres rather than external object storage (S3/GCS) - this app has
-- no existing object-storage dependency to piggyback on, and the volume is
-- genuinely small: a typosquat scan generates at most ~100 candidates, but
-- only the handful that actually resolve (and aren't a wildcard-zone
-- artifact - see V31-era TyposquatChecker false-positive fix) ever get
-- screenshotted, typically 0-5 per target per scan.
--
-- Same current-state-not-history shape as the rest of this table (upserted
-- on every rescan, overwriting the previous screenshot) - so storage stays
-- bounded regardless of how long a target has been monitored, not
-- proportional to scan count.
ALTER TABLE typosquat_candidates
    ADD COLUMN screenshot_png bytea,
    ADD COLUMN visual_similarity_percent smallint;
