-- When Admin.removeAccount began removing the account (R5-08). Removal marks
-- the row first, deletes the account's graph, and deletes the row last, so a
-- removal that fails part way leaves the account listed, as `removing`, until
-- a repeat finishes it. The dispatcher, triggerScan and a scan's begin step
-- leave a marked account alone.
ALTER TABLE accounts ADD COLUMN removing_at INTEGER;
