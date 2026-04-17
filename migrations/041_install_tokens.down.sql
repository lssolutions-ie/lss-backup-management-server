-- Reverses migration 041_install_tokens.sql.
-- WARNING: drops all pending install tokens.

DROP TABLE IF EXISTS node_install_tokens;
