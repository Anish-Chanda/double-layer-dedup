package config_test

import (
	"os"
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
)

func TestLoad_Defaults(t *testing.T) {
	os.Clearenv()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Default values
	if cfg.ServerAddr != ":8080" {
		t.Errorf("expected ServerAddr ':8080', got '%s'", cfg.ServerAddr)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected LogLevel 'info', got '%s'", cfg.LogLevel)
	}
}

func TestLoad_WithEnvOverrides(t *testing.T) {
	// Set custom env vars
	os.Setenv("DSDE_SERVER_ADDR", ":9090")
	os.Setenv("DSDE_LOG_LEVEL", "debug")
	os.Setenv("DSDE_AWS_REGION", "us-west-2")
	os.Setenv("DSDE_KMS_KEY_ID", "test-key-id")
	os.Setenv("DSDE_S3_BUCKET", "test-bucket")
	os.Setenv("DSDE_POSTGRES_DSN", "postgres://user:pass@localhost/db")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() with env returned error: %v", err)
	}

	// Overridden values
	if cfg.ServerAddr != ":9090" {
		t.Errorf("expected ServerAddr ':9090', got '%s'", cfg.ServerAddr)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug', got '%s'", cfg.LogLevel)
	}
	if cfg.AWSRegion != "us-west-2" {
		t.Errorf("expected AWSRegion 'us-west-2', got '%s'", cfg.AWSRegion)
	}
	if cfg.KMSKeyID != "test-key-id" {
		t.Errorf("expected KMSKeyID 'test-key-id', got '%s'", cfg.KMSKeyID)
	}
	if cfg.S3Bucket != "test-bucket" {
		t.Errorf("expected S3Bucket 'test-bucket', got '%s'", cfg.S3Bucket)
	}
	if cfg.PostgresDSN != "postgres://user:pass@localhost/db" {
		t.Errorf("expected PostgresDSN 'postgres://user:pass@localhost/db', got '%s'", cfg.PostgresDSN)
	}
}
