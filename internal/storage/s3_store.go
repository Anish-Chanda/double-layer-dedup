package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ErrInvalidConfig is returned when required config is missing.
var ErrInvalidConfig = fmt.Errorf("AWSRegion and S3Bucket must be set")

// Client wraps the AWS S3 client and bucket name.
type Client struct {
	api    *s3.Client
	bucket string
}

// New creates a new S3 client using AWS_REGION and S3_BUCKET from config.
func New(cfg *config.Config) (*Client, error) {
	if cfg.AWSRegion == "" || cfg.S3Bucket == "" {
		return nil, ErrInvalidConfig
	}
	awsCfg, err := awsConfig.LoadDefaultConfig(context.Background(),
		awsConfig.WithRegion(cfg.AWSRegion),
	)
	if err != nil {
		return nil, err
	}
	return &Client{
		api:    s3.NewFromConfig(awsCfg),
		bucket: cfg.S3Bucket,
	}, nil
}

// PutObject uploads data from the reader to S3 under the given key.
func (c *Client) PutObject(ctx context.Context, key string, body io.Reader) error {
	_, err := c.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
		Body:   body,
	})
	return err
}

// GetObject retrieves the object from S3 and returns its read-closer.
func (c *Client) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := c.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}
