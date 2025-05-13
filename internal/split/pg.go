package split

import (
	"crypto/sha256"
	"encoding/binary"
)

// PG implements Section IV-A: given fea = FG(F) and the full data slice,
// picks B bit-positions via Hᵢ(fea) mod len(data), marks a bit-vector D,
// then splits into pkg2 (D[j]==1) and pkg1 (the rest).
func PG(fea, data []byte, B int) (pkg1, pkg2 []byte) {
	lf := len(data)
	D := make([]bool, lf)

	for i := 1; i <= B; i++ {
		h := sha256.New()
		h.Write(fea)
		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], uint64(i))
		h.Write(idx[:])
		sum := h.Sum(nil)
		pos := binary.BigEndian.Uint64(sum[:8]) % uint64(lf)
		D[pos] = true
	}

	for j, b := range data {
		if D[j] {
			pkg2 = append(pkg2, b)
		} else {
			pkg1 = append(pkg1, b)
		}
	}
	return
}
