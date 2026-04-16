-- Migration 037: HMAC chain head for audit event tamper evidence.
--
-- Each node's audit events carry a per-event HMAC that chains back to the
-- previous event via HMAC-SHA256(psk, prev_hmac || canonical_json(event)).
-- Server verifies the chain on every batch and refuses to advance the ack
-- pointer on a break. See docs/HMAC_CHAIN_SPEC.md.

ALTER TABLE nodes
    ADD COLUMN audit_chain_head VARCHAR(64) NOT NULL DEFAULT '';
