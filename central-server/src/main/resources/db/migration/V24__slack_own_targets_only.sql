-- Lets an org restrict Slack delivery to events about their own (OWN-type) targets only,
-- separate from the existing per-notification-type filter - e.g. an org tracking several
-- competitors may want Slack noise limited to their own domains while still seeing
-- everything in-app.
ALTER TABLE slack_integrations ADD COLUMN own_targets_only boolean NOT NULL DEFAULT false;
