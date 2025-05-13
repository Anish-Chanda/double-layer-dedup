package split_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/split"
)

func TestPG_SumLengths(t *testing.T) {
	data := []byte("abcdef")
	fea := bytes.Repeat([]byte{1}, sha256.Size)
	pkg1, pkg2 := split.PG(fea, data, 3)
	if len(pkg1)+len(pkg2) != len(data) {
		t.Errorf("pkg1+pkg2 total %d, want %d", len(pkg1)+len(pkg2), len(data))
	}
}
