package kms_test

import (
	"context"
	"testing"

	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
	"github.com/Anish-Chanda/double-layer-dedup/internal/kms"
)

func TestNew_InvalidConfig(t *testing.T) {
	// Missing AWSRegion or KMSKeyID should error
	cfg := &config.Config{}
	if _, err := kms.New(cfg); err == nil {
		t.Fatal("expected error for empty AWSRegion/KMSKeyID, got nil")
	}
}

func TestNew_Success(t *testing.T) {
	// If AWS creds/region are set in env, this should succeed.
	cfg := &config.Config{
		AWSRegion: "us-east-2",
		KMSKeyID:  "alias/ExampleKey",
	}
	client, err := kms.New(cfg)
	if err != nil {
		t.Skipf("skipping AWS integration test: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil KMS client")
	}
}

func TestGenerateAndDecryptDataKey(t *testing.T) {
	cfg := &config.Config{
		AWSRegion: "us-east-2",
		KMSKeyID:  "alias/ExampleKey",
	}
	client, err := kms.New(cfg)
	if err != nil {
		t.Skipf("skipping AWS integration test: %v", err)
	}

	plain, cipher, err := client.GenerateDataKey(context.Background())
	if err != nil {
		t.Fatalf("GenerateDataKey error: %v", err)
	}
	if len(plain) == 0 || len(cipher) == 0 {
		t.Fatal("expected non-empty plaintext and ciphertext")
	}

	decrypted, err := client.DecryptDataKey(context.Background(), cipher)
	if err != nil {
		t.Fatalf("DecryptDataKey error: %v", err)
	}
	if len(decrypted) == 0 {
		t.Fatal("expected non-empty decrypted key")
	}
}
