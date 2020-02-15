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
	// defaults to file because local paths were
	// previously given without file:// prefix
	defaultStorageProviderName = "file"

	storageSeparator = "://"
	urlSeparator     = "/"

	httpsScheme = "https"

	providerFile = "file"
	providerGS   = "gs"
	providerS3   = "s3"
)

var storageProviders = []string{providerFile, providerGS, providerS3}

// GetBucket opens and returns a gocloud blob.Bucket based on credentials and a path.
// The path is used to discover which storageProvider should be used.
//
// If the storageProvider file is detected, we don't need any credentials and just open a file bucket
// If no credentials are given, we just fall back to blob.OpenBucket which tries to auto discover credentials
// e.g. via environment variables. For more details, see: https://gocloud.dev/howto/blob/
//
// If we specify credentials and an gs:// or s3:// path is used, credentials must be given in one of the
// following formats:
// * Google Cloud Storage (gs://): a service account key
// * AWS S3 (s3://):
//    {
//      "region": "us-east-1",
//      "s3_force_path_style": true,
//      "access_key": "access_key",
//      "secret_key": "secret_key"
//    }
// * S3-compatible service, e.g. self-hosted Minio (s3://):
//    {
//      "region": "minio",
//      "endpoint": "https://minio-hl-svc.minio-operator-ns:9000",
//      "s3_force_path_style": true,
//      "access_key": "access_key",
//      "secret_key": "secret_key"
//    }
func GetBucket(ctx context.Context, credentials []byte, path string) (*blob.Bucket, error) {
	storageProvider, bucket, _, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}

	if len(credentials) > 0 {
		switch storageProvider {
		case providerGS:
			return getGCSBucket(ctx, credentials, bucket)
		case providerS3:
			return getS3Bucket(ctx, credentials, bucket)
		default:
			return nil, fmt.Errorf("passing credentials is only supported for S3 and GCS not %s", storageProvider)
		}
	}

	bkt, err := blob.OpenBucket(ctx, fmt.Sprintf("%s://%s", storageProvider, bucket))
	if err != nil {
		return nil, fmt.Errorf("error opening file bucket: %v", err)
	}
	return bkt, nil
}

// getGCSBucket opens a gocloud blob.Bucket based on given credentials in the Google
// credential JSON format (see documentation of GetBucket for an example)
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

// s3Credentials are credentials used to access S3 or an S3-compatible storage service
// Endpoint is an optional property. Default is the AWS S3 endpoint. If set, the specified
// endpoint will be used instead.
type s3Credentials struct {
	Region           string `json:"region"`
	Endpoint         string `json:"endpoint"`
	Insecure         bool   `json:"insecure"`
	S3ForcePathStyle bool   `json:"s3_force_path_style"`
	AccessKey        string `json:"access_key"`
	SecretKey        string `json:"secret_key"`
}

// getS3Bucket opens a gocloud blob.Bucket based on given credentials in the format the
// struct s3Credentials defines (see documentation of GetBucket for an example)
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

// ParseStoragePath parses storagePath and returns the storageProvider, bucket and relativePath
// For example gs://prow-artifacts/test.log results in (gs, prow-artifacts, test.log)
// Currently detected storageProviders are GS, S3 and file.
// Paths with a leading / instead of a storageProvider prefix are treated as file paths for backwards
// compatibility reasons.
// File paths are split into a directory and a file. Directory is returned as bucket, file is returned.
// as relativePath.
// For all other paths the first part is treated as storageProvider prefix, the second segment as bucket
// and everything after the bucket as relativePath.
func ParseStoragePath(storagePath string) (storageProvider, bucket, relativePath string, err error) {
	if strings.HasPrefix(storagePath, "/") {
		storagePath = fmt.Sprintf("file://%s", storagePath)
	}
	if strings.HasPrefix(storagePath, "gcs://") {
		storagePath = strings.Replace(storagePath, "gcs://", "gs://", 1)
	}

	parsedPath, err := url.Parse(storagePath)
	if err != nil {
		return "", "", "", fmt.Errorf("unable to parse path %q: %v", storagePath, err)
	}

	storageProvider = parsedPath.Scheme
	if storageProvider == "file" {
		bucket, relativePath = path.Split(parsedPath.Path)
	} else {
		bucket, relativePath = parsedPath.Host, parsedPath.Path
		relativePath = strings.TrimPrefix(relativePath, "/")
	}

	if bucket == "" {
		return "", "", "", fmt.Errorf("could not find bucket in storagePath %q", storagePath)
	}
	return storageProvider, bucket, relativePath, nil
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
