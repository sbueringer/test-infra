package gcs

import (
	"context"
	"gocloud.dev/blob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/gcp"
	"golang.org/x/oauth2/google"
	prowio "k8s.io/test-infra/pkg/io"
	"net/url"
	"path"
)

const (
	httpsScheme = "https"
)

var (
	ProviderName           = "gs"
	StoragePrefix          = "gs"
	StorageSeparator       = "://"
	URLPrefix              = "gs"
	URLSeparator           = "/"
	AlternativeURLPrefixes = []string{"gcs"}
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

func (s *StorageProvider) GetBucket(ctx context.Context, bucketName string) (*blob.Bucket, error) {

	gCreds, err := google.CredentialsFromJSON(ctx, s.Creds, "test")
	if err != nil {
		return nil, err
	}

	client, err := gcp.NewHTTPClient(
		gcp.DefaultTransport(),
		gcp.TokenSource(gCreds.TokenSource))
	if err != nil {
		return nil, err
	}

	return gcsblob.OpenBucket(ctx, client, bucketName, nil)
}

func (s *StorageProvider) SignedURL(ctx context.Context, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error) {
	if len(s.Creds) == 0 {
		artifactLink := &url.URL{
			Scheme: httpsScheme,
			Host:   "storage.googleapis.com",
			Path:   path.Join(bucketName, relativePath),
		}
		return artifactLink.String(), nil
	}
	bucket, err := s.GetBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}

	return bucket.SignedURL(ctx, relativePath, opts)
}
