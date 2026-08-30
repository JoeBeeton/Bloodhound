-- A security review found refresh_tokens had no absolute session lifetime: created_at is set
-- per-row at insert time (including on rotation), so it tells you when THIS token was minted,
-- never when the underlying session originally started. Since every login/refresh resets the
-- expiry to a fresh 30-day window, a token used at least once a month never naturally expires -
-- no ceiling independent of activity. session_started_at is explicitly propagated through
-- rotation (copied from the token being replaced, not DB-defaulted per row - see
-- AuthenticationService#issueTokens) so it stays fixed at the session's true origin across the
-- whole rotation chain, letting AuthenticationService#refresh enforce an absolute cap regardless
-- of how recently the token was last used.
ALTER TABLE refresh_tokens ADD COLUMN session_started_at TIMESTAMPTZ NOT NULL DEFAULT now();
