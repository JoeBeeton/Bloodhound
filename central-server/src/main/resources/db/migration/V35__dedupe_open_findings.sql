-- A real race in the ingestion path (see ResultIngestionService/FindingReconciler) let the same
-- OPEN finding - identical target_id/rule_id/affected_asset - land as more than one row when a
-- module's own reported-findings batch itself contained duplicates (confirmed live:
-- DOCUMENT_METADATA fans out over a target's root plus every subdomain, and the same document
-- linked from more than one of them produced byte-for-byte duplicate findings in one ingest()
-- call). FindingReconciler is now fixed to dedupe within a batch, and the unique index below is
-- the DB-level backstop against any other route to the same race (e.g. two overlapping scan runs
-- for the same target). Before it can be created, existing accidental duplicates must be cleared:
-- keeps the earliest row (by created_at, tied-broken by id) per (target_id, rule_id,
-- affected_asset) among OPEN rows only - RESOLVED/ACCEPTED_RISK history is untouched, since more
-- than one of those sharing a key over time is legitimate (a finding can be resolved and later
-- genuinely reappear - see FindingReconciler's own "treated as brand new" design note).
DELETE FROM findings f
USING (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY target_id, rule_id, affected_asset
               ORDER BY created_at ASC, id ASC
           ) AS rn
    FROM findings
    WHERE status = 'OPEN'
) dupes
WHERE f.id = dupes.id AND dupes.rn > 1;

CREATE UNIQUE INDEX idx_findings_target_rule_asset_open ON findings (target_id, rule_id, affected_asset)
    WHERE status = 'OPEN';
