ALTER TABLE files
  ADD COLUMN fea_hash     BYTEA      NOT NULL,              -- FG(F)
  ADD COLUMN dek_shared   BYTEA      NOT NULL,              -- KMS-encrypted DEK for pkg1
  ADD COLUMN dek_user     BYTEA      NOT NULL;              -- KMS-encrypted DEK for pkg2/pkg4
