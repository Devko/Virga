-- TM-04: before ApiCaller uses a token whose last passed write check
-- (checked_at) is 24 hours old, it runs the check again. The call that runs
-- the recheck claims the row until recheck_until (milliseconds since the
-- epoch), so parallel calls of one account start one recheck. NULL: no claim.
ALTER TABLE vault_tokens ADD COLUMN recheck_until INTEGER;
