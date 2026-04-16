-- Migration 036: snapshot ID set tracking + forensics groundwork.
--
-- Two related additions:
--
-- 1) job_snapshots.snapshot_ids — JSON array of snapshot IDs currently in the
--    repo, post-prune. Lets the server diff prev vs curr per post_run and
--    flag specific disappeared IDs (catches single-snapshot `restic forget`
--    inside the retention window — the snapshot_count detector misses these
--    because count stays at N when one is deleted and the next backup
--    creates one).
--    CLI ships this in JobResult.snapshot_ids in a future v2.x. Until then
--    this column stays NULL and the diff path is a no-op.
--
-- 2) job_anomalies.prev_snapshot_id / curr_snapshot_id — captures both ends
--    of the snapshot pair that triggered the anomaly. Foundation for the
--    "Show deleted files" expander on the anomaly UI: when files-drop or
--    bytes-drop fires on snapshots that still exist, we can run
--    `restic diff prev curr` over the repo-viewer tunnel and list the
--    actually-removed paths.

ALTER TABLE job_snapshots
    ADD COLUMN snapshot_ids JSON NULL AFTER snapshot_id;

ALTER TABLE job_anomalies
    ADD COLUMN prev_snapshot_id VARCHAR(64) NOT NULL DEFAULT '' AFTER snapshot_id,
    ADD COLUMN curr_snapshot_id VARCHAR(64) NOT NULL DEFAULT '' AFTER prev_snapshot_id;
