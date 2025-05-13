package split_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/split"
)

func TestFG_FeatureLength(t *testing.T) {
	// Use any small coefficients; paper doesn't mandate specific values.
	a := []uint64{1, 3, 5}
	m := []uint64{0, 0, 0}
	fg := split.NewFG(a, m)

	// File length = 3 windows of 64 → sliding gives len-63 = 129 positions
	data := bytes.Repeat([]byte("x"), 64*3)
	fea, err := fg.Feature(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(fea) != sha256.Size {
		t.Errorf("expected feature length %d, got %d", sha256.Size, len(fea))
	}
}
