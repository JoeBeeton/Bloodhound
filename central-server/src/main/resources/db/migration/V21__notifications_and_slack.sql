-- In-app notification feed, batched per scan_run (never per-finding/per-subdomain -
-- a single scan can produce hundreds of new findings at once, see notification.NotificationService).
CREATE TABLE notifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    type text NOT NULL,
    severity text NOT NULL,
    title text NOT NULL,
    message text NOT NULL,
    target_id uuid REFERENCES targets(id) ON DELETE CASCADE,
    scan_run_id uuid REFERENCES scan_runs(id) ON DELETE CASCADE,
    is_read boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_notifications_org_created ON notifications (organization_id, created_at DESC);
CREATE INDEX idx_notifications_org_unread ON notifications (organization_id, is_read);

-- One Slack webhook per org. webhook_url is validated application-side (must be a
-- genuine hooks.slack.com URL - see notification.SlackWebhookValidator) before ever
-- being stored, so an admin can't turn this into an open server-side-request-to-
-- arbitrary-URL primitive.
CREATE TABLE slack_integrations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    webhook_url text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    notification_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
