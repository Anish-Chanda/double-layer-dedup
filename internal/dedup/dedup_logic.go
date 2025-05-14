package dedup

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/Anish-Chanda/double-layer-dedup/internal/encryption"
	"github.com/Anish-Chanda/double-layer-dedup/internal/extractor"
)

type DB interface {
	CreateFile(ownerID, filename string) (fileID string, err error)
	ExistsChunk(hash string) (bool, error)
	InsertChunk(hash, s3Key string, isCommon bool) error
	AddFileChunk(fileID, chunkHash string, seq int) error
}

type Store interface {
	PutObject(ctx context.Context, key string, body io.Reader) error
}

type Service struct {
	db    DB
	store Store
}

// New returns a new deduplication service
func New(dbClient DB, storeClient Store) *Service {
	return &Service{
		db:    dbClient,
		store: storeClient,
	}
}

// Process Chunks
// - created a file rec
// - for each chuck:
//   - encrypt via enc
//   - check if chunk exists
//   - if not, upload to store
//   - insert chunk rec
//
// returns fileID
func (s *Service) ProcessChunks(ctx context.Context,
	ownerID, filename string,
	chunks []extractor.ExtractedChunk,
	enc *encryption.Service,
) (string, error) {
	// 1. Create file metadata
	fileID, err := s.db.CreateFile(ownerID, filename)
	if err != nil {
		return "", err
	}

	// 2. Process each chunk
	for i, chunk := range chunks {
		// a. Encrypt
		ct, err := enc.Encrypt(chunk.Data, chunk.IsCommon)
		if err != nil {
			return "", err
		}

		// Build an S3 key
		var key string
		if chunk.IsCommon {
			key = fmt.Sprintf("common/%s", chunk.Hash)
			// b. Only store/record if unseen
			exists, err := s.db.ExistsChunk(chunk.Hash)
			if err != nil {
				return "", err
			}
			if !exists {
				if err := s.store.PutObject(ctx, key, bytes.NewReader(ct)); err != nil {
					return "", err
				}
				if err := s.db.InsertChunk(chunk.Hash, key, true); err != nil {
					return "", err
				}
			}
		} else {
			key = fmt.Sprintf("files/%s/%d-%s", fileID, i, chunk.Hash)
			// c. Always store unique
			if err := s.store.PutObject(ctx, key, bytes.NewReader(ct)); err != nil {
				return "", err
			}
			if err := s.db.InsertChunk(chunk.Hash, key, false); err != nil {
				return "", err
			}
		}

		// d. Link chunk into file sequence
		if err := s.db.AddFileChunk(fileID, chunk.Hash, i); err != nil {
			return "", err
		}
	}

	return fileID, nil
}
