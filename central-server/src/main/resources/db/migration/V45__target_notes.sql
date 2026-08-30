-- A product review found no way to leave context on a target - which environment it is,
-- who owns it, why it's being tracked - beyond the bare hostname and OWN/COMPETITOR/WATCHLIST
-- type. Nullable, no default: an absent note is the overwhelmingly common case (every existing
-- target), not something that needs a placeholder value.
ALTER TABLE targets ADD COLUMN notes TEXT;
