package encryption_test

import (
	"bytes"
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/encryption"
)

func TestEncryption_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	svc, err := encryption.NewWithKey(key)
	if err != nil {
		t.Fatalf("NewWithKey error: %v", err)
	}

	plain := []byte("the quick brown fox")
	for _, common := range []bool{true, false} {
		ct, err := svc.Encrypt(plain, common)
		if err != nil {
			t.Errorf("Encrypt(common=%v) error: %v", common, err)
			continue
		}
		pt, err := svc.Decrypt(ct)
		if err != nil {
			t.Errorf("Decrypt(common=%v) error: %v", common, err)
			continue
		}
		if !bytes.Equal(pt, plain) {
			t.Errorf("Decrypt(common=%v) = %q; want %q", common, pt, plain)
		}
	}
}

func TestEncryption_DeterministicCommon(t *testing.T) {
	key := make([]byte, 32)
	svc, _ := encryption.NewWithKey(key)
	data := []byte("repeatable data")
	c1, _ := svc.Encrypt(data, true)
	c2, _ := svc.Encrypt(data, true)
	if !bytes.Equal(c1, c2) {
		t.Error("expected deterministic encryption for common chunks")
	}
}

func TestEncryption_NondeterministicUnique(t *testing.T) {
	key := make([]byte, 32)
	svc, _ := encryption.NewWithKey(key)
	data := []byte("unique data")
	c1, _ := svc.Encrypt(data, false)
	c2, _ := svc.Encrypt(data, false)
	if bytes.Equal(c1, c2) {
		t.Error("expected nondeterministic encryption for unique chunks")
	}
}
