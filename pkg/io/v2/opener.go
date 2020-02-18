/*
Copyright 2019 The Kubernetes Authors.

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

package v2

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"sync"

	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"

	"k8s.io/test-infra/pkg/io/v2/providers"
)

// Aliases to types in the standard library
type (
	ReadCloser  = io.ReadCloser
	WriteCloser = io.WriteCloser
)

// Opener has methods to retrieve a Reader or Writer for the given path
type Opener interface {
	Reader(ctx context.Context, path string, opts *blob.ReaderOptions) (io.ReadCloser, error)
	Writer(ctx context.Context, path string, opts *blob.WriterOptions) (io.WriteCloser, error)
}

type opener struct {
	credentials        []byte
	cachedBuckets      map[string]*blob.Bucket
	cachedBucketsMutex sync.Mutex
}

// NewOpener returns an opener that can read GCS, S3 and local paths.
// TODO: reference doc of providers.GetBucket, duplicate the doc or just document it here instead of in providers?
func NewOpener(ctx context.Context, credentialsFile string) (Opener, error) {
	var credentials []byte
	var err error
	if credentialsFile != "" {
		credentials, err = ioutil.ReadFile(credentialsFile)
		if err != nil {
			return nil, err
		}
	}
	return &opener{
		credentials:   credentials,
		cachedBuckets: map[string]*blob.Bucket{},
	}, nil
}

// getBucket opens a bucket
// The storageProvider is discovered based on the given path.
// The buckets are cached per bucket name. So we don't open a bucket multiple times in the same process
func (o *opener) getBucket(ctx context.Context, path string) (*blob.Bucket, string, error) {
	_, bucketName, relativePath, err := providers.ParseStoragePath(path)
	if err != nil {
		return nil, "", fmt.Errorf("could not get bucket: %w", err)
	}

	o.cachedBucketsMutex.Lock()
	defer o.cachedBucketsMutex.Unlock()
	if bucket, ok := o.cachedBuckets[bucketName]; ok {
		return bucket, relativePath, nil
	}

	bucket, err := providers.GetBucket(ctx, o.credentials, path)
	if err != nil {
		return nil, "", err
	}
	o.cachedBuckets[bucketName] = bucket
	return bucket, relativePath, nil
}

// Reader opens a reader on the given path
// Internally a bucket is opened and cached. The storageProvider is discovered based on the path.
func (o *opener) Reader(ctx context.Context, path string, opts *blob.ReaderOptions) (io.ReadCloser, error) {
	bucket, relativePath, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	reader, err := bucket.NewReader(ctx, relativePath, opts)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

// Writer opens a writer on the given path
// Internally a bucket is opened and cached. The storageProvider is discovered based on the path.
func (o *opener) Writer(ctx context.Context, path string, opts *blob.WriterOptions) (io.WriteCloser, error) {
	bucket, relativePath, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	writer, err := bucket.NewWriter(ctx, relativePath, opts)
	if err != nil {
		return nil, err
	}
	return writer, nil
}

// ErrNotFoundTest can be used for unit tests to simulate NotFound errors.
// This is required because gocloud doesn't expose its errors.
var ErrNotFoundTest = fmt.Errorf("not found error which should only be used in tests")

// IsNotExist will return true if the error shows that the object does not exist.
func IsNotExist(err error) bool {
	if err == ErrNotFoundTest {
		return true
	}
	return gcerrors.Code(err) == gcerrors.NotFound
}

// LogClose will attempt a close an log any error
func LogClose(c io.Closer) {
	if err := c.Close(); err != nil {
		logrus.WithError(err).Error("Failed to close")
	}
}
