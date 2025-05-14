package extractor

import (
	"crypto/sha256"
	"io"

	"github.com/bits-and-blooms/bloom/v3"
)

// this is one piece of data with its had and common flag
type ExtractedChunk struct {
	Data     []byte
	Hash     string
	IsCommon bool
}

type Extractor struct {
	filter    *bloom.BloomFilter
	chunkSize int
}

// New creates an Extractor with a Bloom filter sized for capacity items
// at the given false‐positive rate, using chunkSize bytes per block.
func New(capacity uint, fpRate float64, chunkSize int) *Extractor {
	return &Extractor{
		filter:    bloom.NewWithEstimates(capacity, fpRate),
		chunkSize: chunkSize,
	}
}

func (e *Extractor) Extract(r io.Reader) ([]ExtractedChunk, error) {
	var chunks []ExtractedChunk
	buf := make([]byte, e.chunkSize)

	for {
		n, err := io.ReadFull(r, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return nil, err
		}

		if n == 0 {
			break
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		sum := sha256.Sum256(data)
		isCommon := e.filter.Test(sum[:])

		if !isCommon {
			e.filter.Add(sum[:])
		}

		chunks = append(chunks, ExtractedChunk{
			Data:     data,
			Hash:     string(sum[:]),
			IsCommon: isCommon,
		})

		if err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		}
	}

	return chunks, nil
}
