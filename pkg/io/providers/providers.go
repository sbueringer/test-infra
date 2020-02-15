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
	"gocloud.dev/blob"
	"strings"
)

const (
	// Required as long as paths without prefix are used
	DefaultStorageProviderName = "gs"
)

var (
	storageProviderCreators        = map[string]StorageProviderCreator{}
	storageProviderPathIdentifiers = map[string]StorageProviderPathIdentifiers{}
)

type StorageProvider interface {
	ParseStoragePath(storagePath string) (bucket, relativePath string, err error)
	GetBucket(ctx context.Context, bucketName string) (*blob.Bucket, error)
	SignedURL(ctx context.Context, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error)
}

type StorageProviderCreator func([]byte) StorageProvider

type StorageProviderPathIdentifiers struct {
	StoragePrefix          string
	StorageSeparator       string
	URLPrefix              string
	URLSeparator           string
	AlternativeURLPrefixes []string
}

func RegisterProvider(name string, fn StorageProviderCreator, config StorageProviderPathIdentifiers) {
	storageProviderCreators[name] = fn
	storageProviderPathIdentifiers[name] = config
}

func GetStorageProvider(credentials []byte, storagePath string) (StorageProvider, error) {
	for spName, sp := range storageProviderPathIdentifiers {
		if strings.HasPrefix(storagePath, sp.StoragePrefix+sp.StorageSeparator) {
			return storageProviderCreators[spName](credentials), nil
		}
	}
	return storageProviderCreators[DefaultStorageProviderName](credentials), nil
}

func GetAllStorageProviderPathIdentifiers() map[string]StorageProviderPathIdentifiers {
	return storageProviderPathIdentifiers
}

func GetStorageProviderPathIdentifiersFromPath(storagePath string) StorageProviderPathIdentifiers {
	for _, sp := range storageProviderPathIdentifiers {
		if strings.HasPrefix(storagePath, sp.StoragePrefix+sp.StorageSeparator) {
			return sp
		}
	}
	return storageProviderPathIdentifiers[DefaultStorageProviderName]
}

func GetStorageProviderPathIdentifiersFromURL(url string) StorageProviderPathIdentifiers {
	for _, sp := range storageProviderPathIdentifiers {
		for _, urlPrefix := range append(sp.AlternativeURLPrefixes, sp.URLPrefix) {
			if strings.HasPrefix(url, urlPrefix+sp.URLSeparator) {
				return sp
			}
		}
	}
	return storageProviderPathIdentifiers[DefaultStorageProviderName]
}
