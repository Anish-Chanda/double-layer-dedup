package rabin_test

import (
	"bytes"
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/rabin"
)

func TestRabinFingerprint_Static(t *testing.T) {
	input := bytes.Repeat([]byte{0xAB}, rabin.DefaultWindow)
	fp := rabin.RabinFingerprint(input)

	if fp == 0 {
		t.Error("RabinFingerprint should not return zero for non-zero input")
	}
}

func TestNewRabin(t *testing.T) {
	r := rabin.NewRabin(rabin.DefaultPoly, rabin.DefaultWindow)

	if r == nil {
		t.Fatal("NewRabin returned nil")
	}

	if r.WindowSize != rabin.DefaultWindow {
		t.Errorf("expected window size %d, got %d", rabin.DefaultWindow, r.WindowSize)
	}

	// Verify that at least one table entry is initialized (non-zero)
	initialized := false
	for i, v := range r.Table {
		if v != 0 {
			initialized = true
			break
		}
		if i > 0 && i == 255 && !initialized {
			t.Error("Rabin table appears uninitialized")
		}
	}
}
