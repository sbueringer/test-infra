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
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcp"
	"golang.org/x/oauth2/google"
)

const (
	// Required as long as paths without prefix are used
	defaultStorageProviderName = "gs"

	storageSeparator = "://"
	urlSeparator     = "/"

	httpsScheme = "https"

	providerFile = "file"
	providerGS   = "gs"
	providerS3   = "s3"
)

var storageProviders = []string{providerFile, providerGS, providerS3}

func GetBucket(ctx context.Context, credentials []byte, path string) (*blob.Bucket, error) {
	storageProvider, bucket, _, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}

	switch storageProvider {
	case providerFile:
		return getFileBucket(bucket)
	case providerGS:
		return getGCSBucket(ctx, credentials, bucket)
	case providerS3:
		return getS3Bucket(ctx, credentials, bucket)
	default:
		return nil, fmt.Errorf("unknown storageProvider: %s", storageProvider)
	}
}

func getFileBucket(bucket string) (*blob.Bucket, error) {
	bkt, err := blob.OpenBucket(context.Background(), "file://"+bucket)
	if err != nil {
		return nil, fmt.Errorf("error opening file bucket: %v", err)
	}
	return bkt, nil
}

func getGCSBucket(ctx context.Context, credentials []byte, bucketName string) (*blob.Bucket, error) {
	googleCredentials, err := google.CredentialsFromJSON(ctx, credentials, storage.ScopeFullControl)
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

type s3Credentials struct {
	Region           string `json:"region"`
	Endpoint         string `json:"endpoint"`
	Insecure         bool   `json:"insecure"`
	S3ForcePathStyle bool   `json:"s3_force_path_style"`
	AccessKey        string `json:"access_key"`
	SecretKey        string `json:"secret_key"`
}

func getS3Bucket(ctx context.Context, creds []byte, bucketName string) (*blob.Bucket, error) {
	s3Credentials := &s3Credentials{}
	if err := json.Unmarshal(creds, s3Credentials); err != nil {
		return nil, fmt.Errorf("error getting S3 credentials from JSON: %v", err)
	}

	staticCredentials := credentials.NewStaticCredentials(s3Credentials.AccessKey, s3Credentials.SecretKey, "")

	sess, err := session.NewSession(&aws.Config{
		Credentials:      staticCredentials,
		Endpoint:         aws.String(s3Credentials.Endpoint),
		DisableSSL:       aws.Bool(s3Credentials.Insecure),
		S3ForcePathStyle: aws.Bool(s3Credentials.S3ForcePathStyle),
		Region:           aws.String(s3Credentials.Region),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating S3 Session: %v", err)
	}

	bkt, err := s3blob.OpenBucket(ctx, sess, bucketName, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening S3 bucket: %v", err)
	}
	return bkt, nil
}

func SignedURL(ctx context.Context, credentials []byte, storagePath string, opts *blob.SignedURLOptions) (string, error) {
	storageProvider, bucketName, relativePath, err := ParseStoragePath(storagePath)
	if err != nil {
		return "", err
	}

	if storageProvider == providerGS && len(credentials) == 0 {
		artifactLink := &url.URL{
			Scheme: httpsScheme,
			Host:   "storage.googleapis.com",
			Path:   path.Join(bucketName, relativePath),
		}
		return artifactLink.String(), nil
	}

	bucket, err := GetBucket(ctx, credentials, storagePath)
	if err != nil {
		return "", err
	}
	defer bucket.Close()
	return bucket.SignedURL(ctx, relativePath, opts)
}

func ParseStoragePath(storagePath string) (storageProvider, bucket, relativePath string, err error) {
	storageProvider = defaultStorageProviderName
	for _, spName := range storageProviders {
		if strings.HasPrefix(storagePath, spName+storageSeparator) {
			storagePath = strings.TrimPrefix(storagePath, spName+storageSeparator)
			storageProvider = spName
			break
		}
	}

	if storageProvider == "file" {
		dir, f := path.Split(storagePath)
		return storageProvider, dir, f, nil
	}

	pathSplit := strings.Split(storagePath, "/")
	if len(pathSplit) < 2 {
		return "", "", "", fmt.Errorf("path %q is not a valid %s path", storagePath, storageProvider)
	}
	return storageProvider, pathSplit[0], path.Join(pathSplit[1:]...), nil
}

func PathHasStorageProviderPrefix(storagePath string) bool {
	for _, spName := range storageProviders {
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
	for _, spName := range storageProviders {
		if strings.HasPrefix(url, spName+urlSeparator) {
			return true
		}
	}
	return false
}

// EncodeStorageURL encodes storage path to URL,
// e.g.: s3://prow-artifacts => s3/prow-artifacts
func EncodeStorageURL(storagePath string) string {
	for _, spName := range storageProviders {
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
	for _, spName := range storageProviders {
		if strings.HasPrefix(url, spName+urlSeparator) {
			return strings.Replace(url, spName+urlSeparator, spName+storageSeparator, 1)
		}
	}
	return url
}
