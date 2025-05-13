package dedup_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/dedup"
	"github.com/Anish-Chanda/double-layer-dedup/internal/encryption"
	"github.com/Anish-Chanda/double-layer-dedup/internal/extractor"
)

// --- fakes ---

type fakeDB struct {
	createdOwner, createdFilename string
	chunkExists                   map[string]bool
	inserted                      []struct {
		hash, key string
		isCommon  bool
	}
	fileChunks []struct {
		fileID, hash string
		seq          int
	}
}

func (f *fakeDB) CreateFile(ownerID, filename string) (string, error) {
	f.createdOwner = ownerID
	f.createdFilename = filename
	return "fake-file-id", nil
}
func (f *fakeDB) ExistsChunk(hash string) (bool, error) {
	return f.chunkExists[hash], nil
}
func (f *fakeDB) InsertChunk(hash, s3Key string, isCommon bool) error {
	f.inserted = append(f.inserted, struct {
		hash, key string
		isCommon  bool
	}{hash, s3Key, isCommon})
	f.chunkExists[hash] = true
	return nil
}
func (f *fakeDB) AddFileChunk(fileID, hash string, seq int) error {
	f.fileChunks = append(f.fileChunks, struct {
		fileID, hash string
		seq          int
	}{fileID, hash, seq})
	return nil
}

type fakeStore struct {
	putKeys []string
	bodies  map[string][]byte
}

func (f *fakeStore) PutObject(ctx context.Context, key string, body io.Reader) error {
	f.putKeys = append(f.putKeys, key)
	if f.bodies == nil {
		f.bodies = make(map[string][]byte)
	}
	data, _ := io.ReadAll(body)
	f.bodies[key] = data
	return nil
}

// --- test ---

func TestProcessChunks(t *testing.T) {
	// Setup fakes
	dbf := &fakeDB{chunkExists: make(map[string]bool)}
	stf := &fakeStore{}
	svc := dedup.New(dbf, stf)

	// Prepare service & chunks
	key := make([]byte, 32)
	encSvc, err := encryption.NewWithKey(key)
	if err != nil {
		t.Fatalf("encryption service init: %v", err)
	}

	data := []byte("foo")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	chunks := []extractor.ExtractedChunk{
		{Data: data, Hash: hash, IsCommon: false}, // unique
		{Data: data, Hash: hash, IsCommon: true},  // common (already inserted)
	}

	// Call ProcessChunks
	fileID, err := svc.ProcessChunks(context.Background(),
		"owner-123", "test.txt", chunks, encSvc,
	)
	if err != nil {
		t.Fatalf("ProcessChunks error: %v", err)
	}
	if fileID != "fake-file-id" {
		t.Errorf("got fileID %q, want fake-file-id", fileID)
	}

	// 1. DB.CreateFile called once
	if dbf.createdOwner != "owner-123" || dbf.createdFilename != "test.txt" {
		t.Errorf("CreateFile got (%s, %s)", dbf.createdOwner, dbf.createdFilename)
	}

	// 2. PutObject called only for the unique chunk
	if len(stf.putKeys) != 1 {
		t.Fatalf("expected 1 PutObject, got %d", len(stf.putKeys))
	}
	expectedKey := "files/fake-file-id/0-" + hash
	if stf.putKeys[0] != expectedKey {
		t.Errorf("unexpected PutObject key: got %s, want %s", stf.putKeys[0], expectedKey)
	}

	// 3. InsertChunk called only once (for the unique chunk)
	if len(dbf.inserted) != 1 {
		t.Fatalf("expected 1 InsertChunk, got %d", len(dbf.inserted))
	}
	if dbf.inserted[0].isCommon {
		t.Errorf("expected inserted[0].isCommon=false, got true")
	}

	// 4. FileChunks links should have both entries
	if len(dbf.fileChunks) != 2 {
		t.Fatalf("expected 2 fileChunks, got %d", len(dbf.fileChunks))
	}
	if dbf.fileChunks[0].seq != 0 || dbf.fileChunks[1].seq != 1 {
		t.Errorf("fileChunks seqs incorrect: %+v", dbf.fileChunks)
	}
}
