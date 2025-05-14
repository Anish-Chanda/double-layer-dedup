CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Store each chunk (common or unique)
CREATE TABLE IF NOT EXISTS chunks (
  chunk_hash   VARCHAR(64) PRIMARY KEY,
  s3_key       TEXT        NOT NULL,
  is_common    BOOLEAN     NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Store each uploaded file
CREATE TABLE IF NOT EXISTS files (
  file_id      UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  owner_id     TEXT        NOT NULL,
  filename     TEXT        NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Map files to their ordered chunks
CREATE TABLE IF NOT EXISTS file_chunks (
  file_id      UUID        NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
  chunk_hash   VARCHAR(64) NOT NULL REFERENCES chunks(chunk_hash) ON DELETE CASCADE,
  seq          INT         NOT NULL,
  PRIMARY KEY (file_id, seq)
);
