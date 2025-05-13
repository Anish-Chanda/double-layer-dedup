package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
)

type Client struct {
	db *sqlx.DB
}

// FileMeta holds the key DSDE metadata for a file.
type FileMeta struct {
	FeaHash   []byte `db:"fea_hash"`
	DekShared []byte `db:"dek_shared"`
	DekUser   []byte `db:"dek_user"`
	Pkg2Len   int    `db:"pkg2_len"`
}

// ChunkInfo holds the s3 key and common‐flag for each stored blob.
type ChunkInfo struct {
	S3Key    string `db:"s3_key"`
	IsCommon bool   `db:"is_common"`
}

// New connects to Postgres using DSDE_POSTGRES_DSN.
func New(cfg *config.Config) (*Client, error) {
	if cfg.PostgresDSN == "" {
		return nil, fmt.Errorf("PostgresDSN must be set")
	}
	db, err := sqlx.Connect("postgres", cfg.PostgresDSN)
	if err != nil {
		return nil, err
	}
	// TODO: tuning
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	return &Client{db: db}, nil
}

// Close the DB connection.
func (c *Client) Close() error {
	return c.db.Close()
}

// ExistsChunk returns true if a chunk hash is already in the table.
func (c *Client) ExistsChunk(hash string) (bool, error) {
	var exists bool
	err := c.db.Get(&exists,
		`SELECT EXISTS(SELECT 1 FROM chunks WHERE chunk_hash=$1)`, hash)
	return exists, err
}

// InsertChunk inserts a new chunk record.
func (c *Client) InsertChunk(hash, s3Key string, isCommon bool) error {
	_, err := c.db.Exec(
		`INSERT INTO chunks (chunk_hash, s3_key, is_common) VALUES ($1, $2, $3)`,
		hash, s3Key, isCommon,
	)
	return err
}

// CreateFile returns the new file’s UUID.
func (c *Client) CreateFile(ownerID, filename string) (string, error) {
	var fileID string
	err := c.db.Get(&fileID,
		`INSERT INTO files (owner_id, filename) VALUES ($1, $2) RETURNING file_id`,
		ownerID, filename,
	)
	return fileID, err
}

// CreateFileWithMeta:
func (c *Client) CreateFileWithMeta(
	ownerID, filename string,
	feaHash, dekShared, dekUser []byte,
	pkg2Len int,
) (string, error) {
	var fileID string
	err := c.db.Get(&fileID, `
      INSERT INTO files
        (owner_id, filename, fea_hash, dek_shared, dek_user, pkg2_len)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING file_id`,
		ownerID, filename, feaHash, dekShared, dekUser, pkg2Len,
	)
	return fileID, err
}

// AddFileChunk links a chunk into a file at the given sequence index.
func (c *Client) AddFileChunk(fileID, chunkHash string, seq int) error {
	_, err := c.db.Exec(
		`INSERT INTO file_chunks (file_id, chunk_hash, seq) VALUES ($1, $2, $3)`,
		fileID, chunkHash, seq,
	)
	return err
}

// GetFileChunkHashes returns ordered chunk hashes for a file.
func (c *Client) GetFileChunkHashes(fileID string) ([]string, error) {
	var hashes []string
	err := c.db.Select(&hashes,
		`SELECT chunk_hash FROM file_chunks WHERE file_id=$1 ORDER BY seq`, fileID)
	return hashes, err
}

func (c *Client) GetFileMeta(ownerID, fileID string) (FileMeta, []ChunkInfo, error) {
	var meta FileMeta
	err := c.db.Get(&meta,
		`SELECT fea_hash, dek_shared, dek_user, pkg2_len
           FROM files
          WHERE file_id=$1 AND owner_id=$2`,
		fileID, ownerID,
	)
	if err != nil {
		return meta, nil, err
	}
	var infos []ChunkInfo
	err = c.db.Select(&infos,
		`SELECT c.s3_key, c.is_common
           FROM file_chunks fc
           JOIN chunks c ON fc.chunk_hash=c.chunk_hash
          WHERE fc.file_id=$1
          ORDER BY fc.seq`,
		fileID,
	)
	return meta, infos, err
}

// Feature holds the shared-DEK record for a given fea_hash.
type Feature struct {
	FeaHash   []byte `db:"fea_hash"`
	DekShared []byte `db:"dek_shared"`
}

// CreateFeature stores a new feature→shared-DEK binding.
func (c *Client) CreateFeature(feaHash, dekShared []byte) error {
	_, err := c.db.Exec(
		`INSERT INTO features(fea_hash, dek_shared) VALUES($1, $2)`,
		feaHash, dekShared,
	)
	return err
}

// GetFeatureByFeaHash loads the existing dek_shared for feaHash.
// Returns sql.ErrNoRows (or wrapping) if none exists yet.
func (c *Client) GetFeatureByFeaHash(feaHash []byte) ([]byte, error) {
	var dek []byte
	err := c.db.Get(&dek,
		`SELECT dek_shared FROM features WHERE fea_hash=$1`,
		feaHash,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}
	return dek, nil
}
