ALTER TABLE nodes
  ADD COLUMN hw_os          VARCHAR(20)  NOT NULL DEFAULT '' AFTER tunnel_public_key,
  ADD COLUMN hw_arch        VARCHAR(20)  NOT NULL DEFAULT '' AFTER hw_os,
  ADD COLUMN hw_cpus        INT          NOT NULL DEFAULT 0  AFTER hw_arch,
  ADD COLUMN hw_hostname    VARCHAR(255) NOT NULL DEFAULT '' AFTER hw_cpus,
  ADD COLUMN hw_ram_bytes   BIGINT       NOT NULL DEFAULT 0  AFTER hw_hostname,
  ADD COLUMN hw_lan_ip      VARCHAR(45)  NOT NULL DEFAULT '' AFTER hw_ram_bytes,
  ADD COLUMN hw_public_ip   VARCHAR(45)  NOT NULL DEFAULT '' AFTER hw_lan_ip,
  ADD COLUMN hw_storage_json TEXT        NOT NULL             AFTER hw_public_ip;
