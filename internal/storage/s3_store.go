package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Client wraps an S3 API client and a bucket name.
type Client struct {
	api    *s3.Client
	bucket string
}

// NewWithClient constructs an S3 client for the given bucket using the provided aws.Config.
// It enables path-style addressing so LocalStack will accept the requests.
func NewWithClient(bucket string, awsCfg aws.Config) (*Client, error) {
	if bucket == "" {
		return nil, fmt.Errorf("bucket name must be set")
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	return &Client{
		api:    client,
		bucket: bucket,
	}, nil
}

// PutObject uploads the data from the reader to S3 under the given key.
func (c *Client) PutObject(ctx context.Context, key string, body io.Reader) error {
	_, err := c.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
		Body:   body,
	})
	return err
}

// GetObject retrieves the object from S3 and returns its ReadCloser.
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
