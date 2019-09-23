package file

import (
	"context"
	"gocloud.dev/blob"
	"gocloud.dev/blob/fileblob"
	prowio "k8s.io/test-infra/pkg/io"
)

var (
	ProviderName           = "file"
	StoragePrefix          = "file"
	StorageSeparator       = ":///"
	URLPrefix              = "file"
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

func createProvider(_ []byte) prowio.StorageProvider {
	return &StorageProvider{}
}

type StorageProvider struct {
}

func (s *StorageProvider) GetBucket(ctx context.Context, bucket string) (*blob.Bucket, error) {
	return fileblob.OpenBucket(bucket, nil)
}

func (s *StorageProvider) SignedURL(ctx context.Context, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error) {
	bucket, err := s.GetBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}

	return bucket.SignedURL(ctx, relativePath, opts)
}
