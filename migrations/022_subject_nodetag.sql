-- Migration 022: Allow node_tag as a subject type in permission_rules.
-- Semantics: treated as a no-op at evaluation time (no user "is a node tag").

ALTER TABLE permission_rules
    MODIFY COLUMN subject_type ENUM('user','user_group','user_tag','node_tag') NOT NULL;
