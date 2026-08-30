-- A product/AppSec review found no audit trail existed anywhere: role changes, password
-- resets, target deletions, and rule toggles all happened invisibly with no record of who
-- did what or when. This covers the highest-value sensitive actions first (identity/access
-- changes, irreversible deletes, detection-suppressing toggles), not literally every write.
--
-- actor_email/actor_display_name are snapshotted at write time, not joined live from users -
-- an audit record should reflect who the actor was identified as *at the time of the action*,
-- not whatever their current profile happens to say later. actor_user_id is kept alongside for
-- optional linking but is nullable and carries no FK, since a record must survive regardless of
-- what later happens to the actor's own account.
--
-- target_id is TEXT, not UUID, and carries no FK to whatever table it names (targets, users,
-- rules_catalog) - those rows can later be deleted (targets, via TargetController#delete) or
-- simply aren't UUID-keyed at all (rules_catalog's rule_id is a natural text key). An audit
-- record must survive the thing it describes being deleted, which a real FK would prevent via
-- cascade.
CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id UUID,
    actor_email TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Backs "most recent activity for this org" - every real read of this table filters and orders this way.
CREATE INDEX idx_audit_log_org_created ON audit_log (organization_id, created_at DESC);
