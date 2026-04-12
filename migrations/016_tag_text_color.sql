ALTER TABLE tags
  ADD COLUMN text_color VARCHAR(7) NOT NULL DEFAULT '#ffffff' AFTER color;
