-- Human-friendly, stable per-target sequential finding identifier
-- ("bh-jaja.co.uk-1", "bh-jaja.co.uk-2", ...) - far easier to reference in
-- conversation or a ticket than the raw UUID primary key. next_finding_number
-- lives on targets (not a single global sequence) so each target's numbering
-- starts fresh at 1 and stays independent of every other target's finding
-- volume - closer to how GitHub issue numbers are per-repo, not global.
ALTER TABLE targets ADD COLUMN next_finding_number INT NOT NULL DEFAULT 1;
ALTER TABLE findings ADD COLUMN display_id TEXT;

-- Backfill existing findings in creation order, per target - ROW_NUMBER() over
-- (target_id, created_at, id) gives a stable, gapless 1..N per target regardless
-- of insertion order across targets.
WITH numbered AS (
    SELECT id, target_id,
           ROW_NUMBER() OVER (PARTITION BY target_id ORDER BY created_at ASC, id ASC) AS rn
    FROM findings
)
UPDATE findings f
SET display_id = 'bh-' || t.hostname || '-' || numbered.rn
FROM numbered
JOIN targets t ON t.id = numbered.target_id
WHERE f.id = numbered.id;

-- Advance each target's counter past whatever was just backfilled (a gapless 1..COUNT(*)
-- per target above means COUNT(*) + 1 is exactly the next number to hand out), so the
-- first new INSERT after this migration continues the sequence instead of restarting at 1
-- and colliding with an existing display_id.
UPDATE targets t
SET next_finding_number = COALESCE(counts.cnt, 0) + 1
FROM (SELECT target_id, COUNT(*) AS cnt FROM findings GROUP BY target_id) counts
WHERE counts.target_id = t.id;

ALTER TABLE findings ALTER COLUMN display_id SET NOT NULL;
-- Scoped to (target_id, display_id), not display_id alone: two different organizations can
-- legitimately track the same hostname (targets.hostname is only unique per-organization, see
-- uq_targets_org_hostname in V3), which would otherwise produce the same display_id under two
-- different targets - display_id is a human-friendly label, not a security-relevant identifier,
-- so that cross-org collision is an acceptable, cosmetic-only tradeoff rather than something
-- worth a heavier uniqueness scheme for.
CREATE UNIQUE INDEX idx_findings_target_display_id ON findings(target_id, display_id);
