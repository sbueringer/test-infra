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
// * Google Cloud Storage (gs://):
//    {
//      "type": "service_account",
//      "project_id": "<project_id>",
//      "private_key_id": "<private_key_id>",
//      "private_key": "<private_key>",
//      "client_email": "<client_email>",
//      "client_id": "<client_id>",
//      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
//      "token_uri": "https://oauth2.googleapis.com/token",
//      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
//      "client_x509_cert_url": "<client_x509_cert_url>"
//    }
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
	if storageProvider == providerFile || len(credentials) == 0 {
		bkt, err := blob.OpenBucket(context.Background(), fmt.Sprintf("%s://%s", storageProvider, bucket))
		if err != nil {
			return nil, fmt.Errorf("error opening file bucket: %v", err)
		}
		return bkt, nil
	}

	switch storageProvider {
	case providerGS:
		return getGCSBucket(ctx, credentials, bucket)
	case providerS3:
		return getS3Bucket(ctx, credentials, bucket)
	default:
		return nil, fmt.Errorf("unknown storageProvider: %s", storageProvider)
	}
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

// ParseStoragePath parses storagePath and returns the storageProvider, bucket and relativePath
// For example gs://prow-artifacts/test.log results in (gs, prow-artifacts, test.log)
// Currently detected storageProviders are GS, S3 and file.
// Paths with a leading / instead of a storageProvider prefix are treated as file paths for backwards
// compatibility reasons.
// File paths are split into a directory and a file. Directory is returned as bucket, file is returned
// as relativePath.
// For all other paths the first part is treated as storageProvider prefix, the second segment as bucket
// and everything after the bucket as relativePath
func ParseStoragePath(storagePath string) (storageProvider, bucket, relativePath string, err error) {
	if strings.HasPrefix(storagePath, "gcs://") {
		storagePath = strings.Replace(storagePath, "gcs://", "gs://", 1)
	}
	for _, spName := range storageProviders {
		if strings.HasPrefix(storagePath, spName+storageSeparator) {
			storagePath = strings.TrimPrefix(storagePath, spName+storageSeparator)
			storageProvider = spName
			break
		}
	}

	// we didn't match one of the registered provider
	if storageProvider == "" {
		// if storagePath starts with / default to file (for compatibility reasons)
		if strings.HasPrefix(storagePath, "/") {
			storageProvider = defaultStorageProviderName
		} else { // if not fail with error
			return "", "", "", fmt.Errorf("couldn't detect storageProvider for path %s", storagePath)
		}
	}

	if storageProvider == "file" {
		dir, f := path.Split(storagePath)
		return storageProvider, dir, f, nil
	}

	pathSplit := strings.Split(storagePath, "/")
	if len(pathSplit) == 1 && pathSplit[0] == "" {
		return "", "", "", fmt.Errorf("path %q is not a valid %s path", storagePath, storageProvider)
	}
	return storageProvider, pathSplit[0], path.Join(pathSplit[1:]...), nil
}
