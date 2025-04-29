package kms

import (
	"context"
	"fmt"

	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// ErrInvalidConfig is returned when required config is missing.
var ErrInvalidConfig = fmt.Errorf("AWSRegion and KMSKeyID must be set")

// Client wraps the AWS KMS client and the key ID to use.
type Client struct {
	api   *kms.Client
	keyID string
}

// New creates a new KMS client using AWS_REGION and KMS_KEY_ID from config.
func New(cfg *config.Config) (*Client, error) {
	if cfg.AWSRegion == "" || cfg.KMSKeyID == "" {
		return nil, ErrInvalidConfig
	}

	awsCfg, err := awsConfig.LoadDefaultConfig(context.Background(),
		awsConfig.WithRegion(cfg.AWSRegion),
	)
	if err != nil {
		return nil, err
	}

	return &Client{
		api:   kms.NewFromConfig(awsCfg),
		keyID: cfg.KMSKeyID,
	}, nil
}

// GenerateDataKey returns a plaintext data key and its KMS-encrypted blob.
func (c *Client) GenerateDataKey(ctx context.Context) (plaintext, ciphertext []byte, err error) {
	out, err := c.api.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(c.keyID),
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, nil, err
	}
	return out.Plaintext, out.CiphertextBlob, nil
}

// DecryptDataKey decrypts a KMS-encrypted data key blob.
func (c *Client) DecryptDataKey(ctx context.Context, encryptedBlob []byte) ([]byte, error) {
	out, err := c.api.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: encryptedBlob,
	})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}
