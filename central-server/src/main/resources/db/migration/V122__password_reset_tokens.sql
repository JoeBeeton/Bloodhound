-- Self-serve "forgot password" (AuthController#forgotPassword/#resetPassword): a short-lived,
-- single-use token emailed to the account, same "handle, not the real thing" shape
-- sso_handoff_codes already uses - deleted on consumption (not just marked), so a consumed or
-- expired code is simply absent, not distinguishable from a forged one. ON DELETE CASCADE: a
-- deleted user can't leave behind a token that would reset a (by then nonexistent, or later
-- reused) password_hash.
CREATE TABLE password_reset_tokens (
    code        TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
