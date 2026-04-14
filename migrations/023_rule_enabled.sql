-- Migration 023: Enabled flag on permission_rules.
ALTER TABLE permission_rules ADD COLUMN enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER priority;
