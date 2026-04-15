-- Migration 034: resolution note on acknowledged anomalies.
--
-- Free-text reason captured at ack time, surfaced as a tooltip on the Ack'd
-- badge. Useful forensics ("acked because dataset rotation, not an attack").

ALTER TABLE job_anomalies
    ADD COLUMN resolution_note VARCHAR(500) NOT NULL DEFAULT '' AFTER acknowledged_at;
