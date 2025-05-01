package rabin

const (
	DefaultPoly   = 0x3DA3358B4DC173 // Irreducible polynomial for Rabin
	DefaultWindow = 64               // Default window size in bytes
	ByteSize      = 8
)

type Rabin struct {
	Poly       uint64
	WindowSize int
	Table      [256]uint64
	Window     []byte
	Pos        int
	Filled     bool
	FP         uint64
}

// NewRabin creates a new Rabin fingerprint struct with the given polynomial and window size
func NewRabin(poly uint64, windowSize int) *Rabin {
	r := &Rabin{
		Poly:       poly,
		WindowSize: windowSize,
		Window:     make([]byte, windowSize),
	}
	r.initTable()
	return r
}

func (r *Rabin) initTable() {
	for b := 0; b < 256; b++ {
		byteVal := uint64(b) << 55 // Shifts by 55 left, same as multiply by 2^55
		for i := 0; i < ByteSize; i++ {
			if (byteVal & (1 << (DefaultWindow - 1))) != 0 {
				byteVal = (byteVal << 1) ^ DefaultPoly // 2*byteVal XOR p
			} else {
				byteVal <<= 1
			}
		}
		r.Table[b] = byteVal
	}
}

// RabinFingerprint computes a static Rabin fingerprint over a window
func RabinFingerprint(data []byte) uint64 {
	var fingerprint uint64
	for _, b := range data {
		fingerprint = (fingerprint << 8) ^ rabinTable[byte(fingerprint>>55)^b]
	}
	return fingerprint
}

var rabinTable [256]uint64

func init() {
	for b := 0; b < 256; b++ {
		byteVal := uint64(b) << 55
		for i := 0; i < 8; i++ {
			if (byteVal & (1 << 63)) != 0 {
				byteVal = (byteVal << 1) ^ DefaultPoly
			} else {
				byteVal <<= 1
			}
		}
		rabinTable[b] = byteVal
	}
}
