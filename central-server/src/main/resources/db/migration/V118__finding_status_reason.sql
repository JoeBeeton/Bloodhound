-- Dismiss/accept-risk had no way to record *why* - an analyst's judgment call (false positive,
-- third-party infrastructure, risk accepted for a documented reason) was lost the moment the
-- button was clicked, with nothing but the audit log's free-text detail string (not shown
-- anywhere in the findings UI itself) to reconstruct it later. Nullable, free text, set only by
-- FindingController#dismissFinding/acceptRiskFinding; reopen clears it back to null since a
-- reopened finding is active again and a stale "why this was dismissed" note would be misleading.
ALTER TABLE findings ADD COLUMN status_reason TEXT;
