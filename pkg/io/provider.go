package io

import (
	"context"
	"fmt"
	"gocloud.dev/blob"
	"path"
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
	GetBucket(ctx context.Context, bucketName string) (*blob.Bucket, error)
	SignedURL(ctx context.Context, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error)
}

type StorageProviderCreator func([] byte) StorageProvider

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

func createProviders(creds []byte) map[string]StorageProvider {
	storageProvider := map[string]StorageProvider{}
	for name, sp := range storageProviderCreators {
		storageProvider[name] = sp(creds)
	}
	return storageProvider
}

func getStorageProviderPathIdentifiersFromPath(storagePath string) StorageProviderPathIdentifiers {
	for _, sp := range storageProviderPathIdentifiers {
		if strings.HasPrefix(storagePath, sp.StoragePrefix+sp.StorageSeparator) {
			return sp
		}
	}
	return storageProviderPathIdentifiers[DefaultStorageProviderName]
}


func PathHasStorageProviderPrefix(storagePath string) bool {
	for _, sp := range storageProviderPathIdentifiers {
		if strings.HasPrefix(storagePath, sp.StoragePrefix+sp.StorageSeparator) {
			return true
		}
	}
	return false
}

func URLHasStorageProviderPrefix(url string) bool {
	for _, sp := range storageProviderPathIdentifiers {
		for _, urlPrefix := range append(sp.AlternativeURLPrefixes, sp.URLPrefix) {
			if strings.HasPrefix(url, urlPrefix+sp.URLSeparator) {
				return true
			}
		}
	}
	return false
}

func getStorageProviderPathIdentifiersFromURL(url string) StorageProviderPathIdentifiers {
	for _, sp := range storageProviderPathIdentifiers {
		for _, urlPrefix := range append(sp.AlternativeURLPrefixes, sp.URLPrefix) {
			if strings.HasPrefix(url, urlPrefix+sp.URLSeparator) {
				return sp
			}
		}
	}
	return storageProviderPathIdentifiers[DefaultStorageProviderName]
}

func ParseStoragePath(storagePath string) (bucket, relativePath string, err error) {
	sp := getStorageProviderPathIdentifiersFromPath(storagePath)
	if !strings.HasPrefix(storagePath, sp.StoragePrefix+sp.StorageSeparator) {
		return "", "", fmt.Errorf("path is not a valid %s path: %s", sp.StoragePrefix, storagePath)
	}
	storagePath = strings.TrimPrefix(storagePath, sp.StoragePrefix+sp.StorageSeparator)

	pathSplit := strings.Split(storagePath, "/")
	if len(pathSplit) < 2 {
		return "", "", fmt.Errorf("path is not a valid %s path: %s", sp.StoragePrefix, storagePath)
	}
	return pathSplit[0], path.Join(pathSplit[1:]...), nil
}

// s3://prow-artifacts => s3/prow-artifacts
// TODO: think about changing type of storagePath to url.URL
func EncodeStorageURL(storagePath string) string {
	sp := getStorageProviderPathIdentifiersFromPath(storagePath)
	if strings.HasPrefix(storagePath, sp.StoragePrefix+sp.StorageSeparator) {
		return strings.Replace(storagePath, sp.StoragePrefix+sp.StorageSeparator, sp.URLPrefix+sp.URLSeparator, 1)
	}
	return storagePath
}

// s3/prow-artifacts => s3://prow-artifacts
// TODO: think about changing type of storagePath to url.URL
func DecodeStorageURL(url string) string {
	sp := getStorageProviderPathIdentifiersFromURL(url)
	for _, urlPrefix := range append(sp.AlternativeURLPrefixes, sp.URLPrefix) {
		if strings.HasPrefix(url, urlPrefix+sp.URLSeparator) {
			return strings.Replace(url, urlPrefix+sp.URLSeparator, sp.StoragePrefix+sp.StorageSeparator, 1)
		}
	}
	return url
}

// TODO: not sure if it's worth having a separate method, but for now it's easier
// to track where we're joining storagePath (and where the regular path.Join doesn't
// work because it removes one of the slashes in e.g. s3://)
func JoinStoragePath(elem ... string) string {
	return strings.Join(elem, "/")
}
