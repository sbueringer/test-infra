/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gcs

import (
	"cloud.google.com/go/storage"
	"context"
	"fmt"
	"gocloud.dev/blob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/gcp"
	"golang.org/x/oauth2/google"
	"k8s.io/test-infra/pkg/io/providers"
	"k8s.io/test-infra/pkg/io/providers/util"
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

var identifiers = providers.StorageProviderPathIdentifiers{
	StoragePrefix:          StoragePrefix,
	StorageSeparator:       StorageSeparator,
	URLPrefix:              URLPrefix,
	URLSeparator:           URLSeparator,
	AlternativeURLPrefixes: AlternativeURLPrefixes,
}

func init() {
	providers.RegisterProvider(ProviderName, createProvider, identifiers)
}

func createProvider(credentials []byte) providers.StorageProvider {
	return &StorageProvider{
		Credentials: credentials,
	}
}

type StorageProvider struct {
	Credentials []byte
}

func (s *StorageProvider) ParseStoragePath(storagePath string) (bucket, relativePath string, err error) {
	return util.ParseStoragePath(identifiers, storagePath)
}

func (s *StorageProvider) GetBucket(ctx context.Context, bucketName string) (*blob.Bucket, error) {
	googleCredentials, err := google.CredentialsFromJSON(ctx, s.Credentials, storage.ScopeFullControl)
	if err != nil {
		return nil, fmt.Errorf("error getting Google credentials from JSON: %v", err)
	}

	client, err := gcp.NewHTTPClient(
		gcp.DefaultTransport(),
		gcp.TokenSource(googleCredentials.TokenSource))
	if err != nil {
		return nil, fmt.Errorf("error creating GCP Http Client: %v", err)
	}

	bkt, err := gcsblob.OpenBucket(ctx, client, bucketName, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening GCS bucket: %v", err)
	}
	return bkt, nil
}

func (s *StorageProvider) SignedURL(ctx context.Context, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error) {
	if len(s.Credentials) == 0 {
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
