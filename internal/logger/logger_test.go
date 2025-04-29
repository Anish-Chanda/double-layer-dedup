package logger_test

import (
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/logger"
)

func TestNewLogger_ValidLevel(t *testing.T) {
	log := logger.New("debug")
	if log == nil {
		t.Error("Expected non-nil logger for valid level")
	}
}

func TestNewLogger_InvalidLevel(t *testing.T) {
	log := logger.New("invalid-level")
	if log == nil {
		t.Error("Expected non-nil logger fallback for invalid level")
	}
}
