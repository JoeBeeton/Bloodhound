-- Distinct external origins a hostname's homepage <script>/<iframe> tags
-- actually load from (analytics, tag managers, chat/embed widgets) - a
-- current-state snapshot alongside the existing technologies column, same
-- "overwritten each scan, no history" reasoning from the V11 comment.
ALTER TABLE fingerprints
    ADD COLUMN third_party_origins JSONB NOT NULL DEFAULT '[]'::jsonb;
