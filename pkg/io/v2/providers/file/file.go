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

package file

import (
	"context"
	"fmt"
	"path"
	"strings"

	"gocloud.dev/blob"
	"gocloud.dev/blob/fileblob"

	"k8s.io/test-infra/pkg/io/v2/providers"
)

var (
	ProviderName           = "file"
	StoragePrefix          = "file"
	StorageSeparator       = "://"
	URLPrefix              = "file"
	URLSeparator           = "/"
	AlternativeURLPrefixes = []string{}
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

func createProvider(_ []byte) providers.StorageProvider {
	return &StorageProvider{}
}

type StorageProvider struct {
}

func (s *StorageProvider) ParseStoragePath(storagePath string) (bucket, relativePath string, err error) {
	if !strings.HasPrefix(storagePath, identifiers.StoragePrefix+identifiers.StorageSeparator) {
		return "", "", fmt.Errorf("path is not a valid %s path: %s", identifiers.StoragePrefix, storagePath)
	}
	storagePath = strings.TrimPrefix(storagePath, identifiers.StoragePrefix+identifiers.StorageSeparator)

	dir, file := path.Split(storagePath)
	return dir, file, nil
}

func (s *StorageProvider) GetBucket(_ context.Context, bucket string) (*blob.Bucket, error) {
	bkt, err := fileblob.OpenBucket(bucket, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening file bucket: %v", err)
	}
	return bkt, nil
}

func (s *StorageProvider) SignedURL(ctx context.Context, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error) {
	bucket, err := s.GetBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}

	return bucket.SignedURL(ctx, relativePath, opts)
}
