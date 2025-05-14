-- 0003_features.up.sql
CREATE TABLE IF NOT EXISTS features (
  fea_hash   BYTEA PRIMARY KEY,              -- FG(F)
  dek_shared BYTEA NOT NULL,                 -- first-uploader’s encrypted DEK
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
