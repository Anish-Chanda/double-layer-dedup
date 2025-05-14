package extractor_test

import (
	"bytes"
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/extractor"
)

func TestExtractor_RepeatedPattern(t *testing.T) {
	// Prepare data: "foo" repeated 4 times → 4 identical chunks
	data := bytes.Repeat([]byte("foo"), 4)
	ext := extractor.New(
		/*capacity=*/ 10, // up to 10 unique chunks
		/*fpRate=*/ 0.01, // 1% false positive rate
		/*chunkSize=*/ 3, // read in 3‐byte pieces
	)
	chunks, err := ext.Extract(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}
	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d", len(chunks))
	}

	// Expect first chunk unique, the next 3 marked common
	for i, c := range chunks {
		wantCommon := i > 0
		if c.IsCommon != wantCommon {
			t.Errorf("chunk %d: IsCommon expected %v, got %v", i, wantCommon, c.IsCommon)
		}
		// hashes should all match
		if c.Hash != chunks[0].Hash {
			t.Errorf("chunk %d: hash mismatch; expected %s, got %s", i, chunks[0].Hash, c.Hash)
		}
	}
}

func TestExtractor_DifferentChunks(t *testing.T) {
	// Data: "abc","def","ghi" → all unique
	data := []byte("abcdefghi")
	ext := extractor.New(10, 0.01, 3)
	chunks, err := ext.Extract(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if c.IsCommon {
			t.Errorf("chunk %d: expected unique, got common", i)
		}
	}
}
