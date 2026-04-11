ALTER TABLE nodes
  ADD COLUMN tunnel_port       INT         NULL AFTER last_seen_at,
  ADD COLUMN tunnel_connected  TINYINT(1)  NOT NULL DEFAULT 0 AFTER tunnel_port,
  ADD COLUMN tunnel_public_key TEXT        NULL AFTER tunnel_connected;
