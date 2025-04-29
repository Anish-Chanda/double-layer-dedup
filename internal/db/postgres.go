package db

// TODO: add integration tests using localstack?
import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
)

type Client struct {
	db *sqlx.DB
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
