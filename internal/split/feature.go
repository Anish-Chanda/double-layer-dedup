package split

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/aclements/go-rabin/rabin"
)

// FG implements Section IV-C1: sliding-window Rabin fingerprints → sub-features.
type FG struct {
	table  *rabin.Table
	a, m   []uint64
	window int
}

// NewFG constructs an FG with Rabin.Window=64 and the given coefficient slices aᵢ, mᵢ.
func NewFG(a, m []uint64) *FG {
	// Poly64 and window=64 per paper
	table := rabin.NewTable(rabin.Poly64, 64)
	return &FG{table: table, a: a, m: m, window: 64}
}

// Feature reads the entire file from r, slides a 64-byte Rabin window at each byte,
// computes Pi = current 64-byte fingerprint, maps to si = aᵢ·Pi + mᵢ mod 2⁶⁴,
// feeds each si (big-endian) into SHA256, and returns the final 32-byte digest.
func (f *FG) Feature(r io.Reader) ([]byte, error) {
	// Rolling-hash over windows
	hashRabin := rabin.New(f.table)
	// SHA256 over concatenated sub-features (streaming)
	hashSum := sha256.New()

	br := bufio.NewReader(r)
	var (
		totalBytes int // total bytes fed into hashRabin
		idx        int // index for selecting aᵢ, mᵢ
		buf        = make([]byte, 4096)
	)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			for i := 0; i < n; i++ {
				b := buf[i : i+1]
				hashRabin.Write(b)
				totalBytes++
				if totalBytes >= f.window {
					pi := hashRabin.Sum64()
					ai := f.a[idx%len(f.a)]
					mi := f.m[idx%len(f.m)]
					si := ai*pi + mi
					var be [8]byte
					binary.BigEndian.PutUint64(be[:], si)
					hashSum.Write(be[:])
					idx++
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return hashSum.Sum(nil), nil
}
