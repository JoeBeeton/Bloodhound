-- Tracks each target's progress through BucketNameGenerator's large (18,696-term) wordlist -
-- crossed with a stem and 5 providers that's ~187,000 requests, far more than any single deep
-- scan's budget allows. Rather than a full-history table, this is a current-state pointer:
-- one row per target, advanced after every BUCKET_BRUTE_FORCE run (see
-- BucketBruteForceIngestionService), so each successive deep scan picks up the next slice of the
-- wordlist instead of re-running (or never reaching) the same names every time.

CREATE TABLE bucket_brute_force_wordlist_cursor (
    target_id   UUID PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
    position    INT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
