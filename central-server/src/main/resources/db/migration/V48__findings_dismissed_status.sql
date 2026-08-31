-- A product review found findings had no manual override at all: FindingReconciler's automatic
-- OPEN->RESOLVED transition (see its own javadoc) only fires when a scan no longer detects an
-- issue, so a false positive or an accepted-risk finding just sat as OPEN forever with no way for
-- an analyst to say "reviewed, doesn't need action" short of waiting for the underlying condition
-- to change. DISMISSED is a sticky human override: FindingController#dismissFinding/reopenFinding
-- are the only things that ever set or clear it, and FindingReconciler never touches a DISMISSED
-- finding either direction - it only ever sees status='OPEN' rows in the first place (see
-- FindingRepository#findOpenKeys), so a dismissed finding stays dismissed even if a later scan
-- would otherwise still detect the same issue, until a human explicitly reopens it. Confirmed the
-- exact constraint name live (conname query against pg_constraint) rather than assuming Postgres's
-- default auto-generated naming.
ALTER TABLE findings DROP CONSTRAINT findings_status_check;
ALTER TABLE findings ADD CONSTRAINT findings_status_check CHECK (status IN ('OPEN', 'RESOLVED', 'ACCEPTED_RISK', 'DISMISSED'));
