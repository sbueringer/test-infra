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

package providers

import (
	"context"
	"fmt"
	"k8s.io/test-infra/pkg/io/v2/providers/file"
	"k8s.io/test-infra/pkg/io/v2/providers/gcs"
	"k8s.io/test-infra/pkg/io/v2/providers/s3"
	"path"
	"strings"

	"gocloud.dev/blob"
)

const (
	// Required as long as paths without prefix are used
	defaultStorageProviderName = "gs"

	storageSeparator = "://"
	urlSeparator     = "/"
)

var (
	storageProviders = map[string]StorageProvider{}
)

func init() {
	storageProviders = map[string]StorageProvider{
		file.ProviderName: file.Provider,
		gcs.ProviderName:  gcs.Provider,
		s3.ProviderName:   s3.Provider,
	}
}

type StorageProvider interface {
	GetBucket(ctx context.Context, credentials []byte, bucketName string) (*blob.Bucket, error)
	SignedURL(ctx context.Context, credentials []byte, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error)
}

func GetStorageProvider(storagePath string) (StorageProvider, error) {
	for spName := range storageProviders {
		if strings.HasPrefix(storagePath, spName+storageSeparator) {
			return storageProviders[spName], nil
		}
	}
	return storageProviders[defaultStorageProviderName], nil
}

func ParseStoragePath(storagePath string) (bucket, relativePath string, err error) {
	var storageProvider string
	for spName := range storageProviders {
		if strings.HasPrefix(storagePath, spName+storageSeparator) {
			storagePath = strings.TrimPrefix(storagePath, storagePath+storageSeparator)
			storageProvider = spName
			break
		}
	}

	if storageProvider == "file" {
		dir, f := path.Split(storagePath)
		return dir, f, nil
	}

	pathSplit := strings.Split(storagePath, "/")
	if len(pathSplit) < 2 {
		return "", "", fmt.Errorf("path %q is not a valid %s path", storagePath, storageProvider)
	}
	return pathSplit[0], path.Join(pathSplit[1:]...), nil

}

func PathHasStorageProviderPrefix(storagePath string) bool {
	for spName := range storageProviders {
		if strings.HasPrefix(storagePath, spName+storageSeparator) {
			return true
		}
	}
	return false
}

func URLHasStorageProviderPrefix(url string) bool {
	if strings.HasPrefix(url, "gcs://") {
		url = strings.Replace(url, "gcs://", "gs://", 1)
	}
	for spName := range storageProviders {
		if strings.HasPrefix(url, spName+urlSeparator) {
			return true
		}
	}
	return false
}

// EncodeStorageURL encodes storage path to URL,
// e.g.: s3://prow-artifacts => s3/prow-artifacts
func EncodeStorageURL(storagePath string) string {
	for spName := range storageProviders {
		if strings.HasPrefix(storagePath, spName+storageSeparator) {
			return strings.Replace(storagePath, spName+storageSeparator, spName+urlSeparator, 1)
		}
	}
	return storagePath
}

// DecodeStorageURL decodes storage URL to path,
// e.g.: s3/prow-artifacts => s3://prow-artifacts
func DecodeStorageURL(url string) string {
	if strings.HasPrefix(url, "gcs/") {
		url = strings.Replace(url, "gcs/", "gs/", 1)
	}
	for spName := range storageProviders {
		if strings.HasPrefix(url, spName+urlSeparator) {
			return strings.Replace(url, spName+urlSeparator, spName+storageSeparator, 1)
		}
	}
	return url
}
