-- Migration 033: Aggressive "node went silent" detector.
--
-- The existing OfflineThresholdMinutes (default 10) is fine for "this node
-- is gone" but doesn't fire fast enough to flag attacker-stopped daemons
-- at 03:00. silent_alert_threshold_minutes is a SHORTER deadline that fires
-- a host-level alert as soon as a node misses a single heartbeat (default 7).

ALTER TABLE server_tuning
    ADD COLUMN silent_alert_threshold_minutes INT UNSIGNED NOT NULL DEFAULT 7;
