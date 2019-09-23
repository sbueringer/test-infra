package s3

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"gocloud.dev/blob"
	"gocloud.dev/blob/s3blob"
	prowio "k8s.io/test-infra/pkg/io"
)

var (
	ProviderName           = "s3"
	StoragePrefix          = "s3"
	StorageSeparator       = "://"
	URLPrefix              = "s3"
	URLSeparator           = "/"
	AlternativeURLPrefixes = []string{}
)

func init() {
	prowio.RegisterProvider(ProviderName, createProvider, prowio.StorageProviderPathIdentifiers{
		StoragePrefix:          StoragePrefix,
		StorageSeparator:       StorageSeparator,
		URLPrefix:              URLPrefix,
		URLSeparator:           URLSeparator,
		AlternativeURLPrefixes: AlternativeURLPrefixes,
	})
}

func createProvider(creds []byte) prowio.StorageProvider {
	return &StorageProvider{
		Creds: creds,
	}
}

type StorageProvider struct {
	Creds []byte
}

type s3Credentials struct {
	Region           string `json:"region"`
	Bucket           string `json:"bucket"`
	Endpoint         string `json:"endpoint"`
	Insecure         bool   `json:"insecure"`
	S3ForcePathStyle bool   `json:"s3_force_path_style"`
	AccessKey        string `json:"access_key"`
	SecretKey        string `json:"secret_key"`
}

func (s *StorageProvider) GetBucket(ctx context.Context, bucketName string) (*blob.Bucket, error) {

	s3Creds := &s3Credentials{}
	if err := json.Unmarshal(s.Creds, s3Creds); err != nil {
		return nil, err
	}

	staticCredentials := credentials.NewStaticCredentials(s3Creds.AccessKey, s3Creds.SecretKey, "")

	sess, err := session.NewSession(&aws.Config{
		Credentials:      staticCredentials,
		Endpoint:         aws.String(s3Creds.Endpoint),
		DisableSSL:       aws.Bool(s3Creds.Insecure),
		S3ForcePathStyle: aws.Bool(s3Creds.S3ForcePathStyle),
		Region:           aws.String(s3Creds.Region),
	})
	if err != nil {
		return nil, err
	}

	return s3blob.OpenBucket(ctx, sess, bucketName, nil)
}

func (s *StorageProvider) SignedURL(ctx context.Context, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error) {
	bucket, err := s.GetBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}
	return bucket.SignedURL(ctx, relativePath, opts)
}
