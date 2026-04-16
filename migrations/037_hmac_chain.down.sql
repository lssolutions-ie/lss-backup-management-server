-- Reverses migration 037_hmac_chain.sql.

ALTER TABLE nodes
    DROP COLUMN audit_chain_head;
