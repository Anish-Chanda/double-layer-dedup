package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Service handles DEK generation (via KMS) and chunk encrypt/decrypt.
type Service struct {
	dekPlain  []byte      // plaintext data key
	dekCipher []byte      // KMS-encrypted data key blob
	aead      cipher.AEAD // AES-GCM AEAD for encryption/decryption
}

// NewWithKey builds a Service from a raw 32-byte key (for tests or manual DEK).
func NewWithKey(rawKey []byte) (*Service, error) {
	if len(rawKey) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Service{dekPlain: rawKey, aead: aead}, nil
}

// New uses KMS to generate a fresh data key for encryption.
func New(ctx context.Context, kmsClient *kms.Client, keyID string) (*Service, error) {
	out, err := kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &keyID,
		KeySpec: "AES_256",
	})
	if err != nil {
		return nil, err
	}
	// out.Plaintext is 32 bytes
	svc, err := NewWithKey(out.Plaintext)
	if err != nil {
		return nil, err
	}
	svc.dekCipher = out.CiphertextBlob
	return svc, nil
}

// DEKCipher returns the KMS-encrypted data key blob (for metadata storage).
func (s *Service) DEKCipher() []byte {
	return s.dekCipher
}

// Encrypt encrypts chunk data. For common==true it uses deterministic nonce
// derived from SHA-256(data); otherwise random nonce for probabilistic encryption.
// The output is nonce||ciphertext.
func (s *Service) Encrypt(data []byte, common bool) ([]byte, error) {
	nonceSize := s.aead.NonceSize()
	var nonce []byte
	if common {
		sum := sha256.Sum256(data)
		nonce = sum[:nonceSize]
	} else {
		nonce = make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
	}
	ct := s.aead.Seal(nil, nonce, data, nil)
	return append(nonce, ct...), nil
}

// Decrypt reverses Encrypt by splitting nonce||ciphertext.
func (s *Service) Decrypt(blob []byte) ([]byte, error) {
	nonceSize := s.aead.NonceSize()
	if len(blob) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := blob[:nonceSize]
	ct := blob[nonceSize:]
	return s.aead.Open(nil, nonce, ct, nil)
}
