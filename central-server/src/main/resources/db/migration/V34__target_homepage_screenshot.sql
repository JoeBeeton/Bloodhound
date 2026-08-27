-- The real target's own homepage screenshot, for a visual side-by-side against
-- the typosquat candidate thumbnails in the Brand Protection panel - TyposquatChecker
-- already captures this once per scan to compute the perceptual-hash baseline every
-- candidate is compared against, but previously discarded the bytes after hashing.
-- Lives directly on targets (not typosquat_candidates, which is scoped to lookalike
-- candidates specifically) since this is a property of the target itself, not a
-- squatting candidate. Same current-state (overwritten each scan), not history.
ALTER TABLE targets ADD COLUMN homepage_screenshot_png bytea;
