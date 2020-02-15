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

package s3

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"gocloud.dev/blob"
	"gocloud.dev/blob/s3blob"

	"k8s.io/test-infra/pkg/io/providers"
	"k8s.io/test-infra/pkg/io/providers/util"
)

var (
	ProviderName           = "s3"
	StoragePrefix          = "s3"
	StorageSeparator       = "://"
	URLPrefix              = "s3"
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

func createProvider(credentials []byte) providers.StorageProvider {
	return &StorageProvider{
		Credentials: credentials,
	}
}

type StorageProvider struct {
	Credentials []byte
}

type s3Credentials struct {
	Region           string `json:"region"`
	Bucket           string `json:"bucket"`
	Endpoint         string `json:"endpoint"`
	Insecure         bool   `json:"insecure"`
	S3ForcePathStyle bool   `json:"s3_force_path_style"`
	AccessKey        string `json:"access_key"`
	SecretKey        string `json:"secret_key"`
}

func (s *StorageProvider) ParseStoragePath(storagePath string) (bucket, relativePath string, err error) {
	return util.ParseStoragePath(identifiers, storagePath)
}

func (s *StorageProvider) GetBucket(ctx context.Context, bucketName string) (*blob.Bucket, error) {

	s3Credentials := &s3Credentials{}
	if err := json.Unmarshal(s.Credentials, s3Credentials); err != nil {
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

func (s *StorageProvider) SignedURL(ctx context.Context, bucketName, relativePath string, opts *blob.SignedURLOptions) (string, error) {
	bucket, err := s.GetBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}

	return bucket.SignedURL(ctx, relativePath, opts)
}
