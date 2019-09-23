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

package io

import (
	"cloud.google.com/go/storage"
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"io"
	"io/ioutil"
	"k8s.io/test-infra/prow/errorutil"
	"os"
	"strings"
	"sync"
)

// Aliases to types in the standard library
type (
	ReadCloser  = io.ReadCloser
	WriteCloser = io.WriteCloser
)

// Opener has methods to read and write paths
type Opener interface {
	Reader(ctx context.Context, path string, opts *blob.ReaderOptions) (io.ReadCloser, error)
	RangeReader(ctx context.Context, path string, offset, length int64, opts *blob.ReaderOptions) (io.ReadCloser, error)
	ReadObject(ctx context.Context, path string) ([]byte, error)
	Attributes(ctx context.Context, path string) (attrs *blob.Attributes, err error)
	SignedURL(ctx context.Context, path string, opts *blob.SignedURLOptions) (string, error)

	ListSubPaths(ctx context.Context, path string, matchFns ...func(*blob.ListObject) bool) ([]string, error)
	ListSubPathsIter(ctx context.Context, path string) (*blob.ListIterator, error)
	ListSubDirs(ctx context.Context, path string) ([]string, error)

	Writer(ctx context.Context, path string, opts *blob.WriterOptions) (io.WriteCloser, error)
	Upload(ctx context.Context, uploads map[string]UploadFunc) error

	// Workaround to retrieve the storageClient for spyglass/testgrid.go
	// because it calls an external lib which only works with GCS
	GetGCSClient(ctx context.Context) (*storage.Client, error)
}

type opener struct {
	storageProviders map[string]StorageProvider
}

// NewOpener returns an opener that can read GCS and local paths.
// TODO: remove ctx
func NewOpener(ctx context.Context, credentialsFile string) (Opener, error) {
	creds, err := ioutil.ReadFile(credentialsFile)
	if err != nil {
		return nil, err
	}
	return &opener{
		storageProviders: createProviders(creds),
	}, nil
}

type readerCloser struct {
	r *blob.Reader
	b *blob.Bucket
}

func (rc readerCloser) Read(p []byte) (n int, err error) {
	return rc.r.Read(p)
}

func (rc readerCloser) Close() error {
	if err := rc.r.Close(); err != nil {
		return err
	}
	if err := rc.b.Close(); err != nil {
		return err
	}
	return nil
}

func (o *opener) Reader(ctx context.Context, path string, opts *blob.ReaderOptions) (io.ReadCloser, error) {
	bucket, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	_, relativePath, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}
	reader, err := bucket.NewReader(ctx, relativePath, opts)
	if err != nil {
		return nil, err
	}
	return readerCloser{reader, bucket}, nil
}

func (o *opener) RangeReader(ctx context.Context, path string, offset, length int64, opts *blob.ReaderOptions) (io.ReadCloser, error) {
	bucket, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	_, relativePath, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}
	reader, err := bucket.NewRangeReader(ctx, relativePath, offset, length, opts)
	if err != nil {
		return nil, err
	}
	return readerCloser{reader, bucket}, nil
}

func (o *opener) ReadObject(ctx context.Context, path string) ([]byte, error) {
	_, relativePath, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}
	b, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	return b.ReadAll(ctx, relativePath)
}

func (o *opener) Attributes(ctx context.Context, path string) (*blob.Attributes, error) {
	_, relativePath, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}
	b, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}

	return b.Attributes(ctx, relativePath)
}

func (o *opener) SignedURL(ctx context.Context, path string, opts *blob.SignedURLOptions) (string, error) {
	sp, err := o.getStorageProvider(path)
	if err != nil {
		return "", nil
	}
	bucket, relativePath, err := ParseStoragePath(path)
	if err != nil {
		return "", err
	}
	return sp.SignedURL(ctx, bucket, relativePath, opts)
}

// Lists all paths with given path. If matchFuncs are given, all must match so that the obj
// is included in the result
func (o *opener) ListSubPaths(ctx context.Context, path string, matchFns ...func(*blob.ListObject) bool) ([]string, error) {
	paths := []string{}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	_, relativePath, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}
	pathPrefix := strings.TrimSuffix(path, relativePath +"/")

	it, err := o.ListSubPathsIter(ctx, path)
	if err != nil {
		return nil, err
	}
	for {
		obj, err := it.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return paths, err
		}
		matched := true
		for _, matchFn := range matchFns {
			if !matchFn(obj) {
				matched = false
			}
		}
		if matched {
			paths = append(paths, fmt.Sprintf("%s/%s", pathPrefix, obj.Key))
		}
	}
	return paths, nil
}

func (o *opener) ListSubPathsIter(ctx context.Context, path string) (*blob.ListIterator, error) {
	_, relativePath, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}
	q := &blob.ListOptions{
		Prefix:    relativePath + "/",
		Delimiter: "/",
	}
	bucket, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	return bucket.List(q), nil
}

func (o *opener) ListSubDirs(ctx context.Context, path string) ([]string, error) {
	return o.ListSubPaths(ctx, path, func(obj *blob.ListObject) bool {
		return obj.IsDir
	})
}

type writerCloser struct {
	w *blob.Writer
	b *blob.Bucket
}

func (rc writerCloser) Write(p []byte) (n int, err error) {
	return rc.w.Write(p)
}

func (rc writerCloser) Close() error {
	if err := rc.w.Close(); err != nil {
		return err
	}
	if err := rc.b.Close(); err != nil {
		return err
	}
	return nil
}

// Writer returns a writer that overwrites the path.
func (o *opener) Writer(ctx context.Context, path string, opts *blob.WriterOptions) (io.WriteCloser, error) {
	bucket, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	_, relativePath, err := ParseStoragePath(path)
	if err != nil {
		return nil, err
	}
	writer, err := bucket.NewWriter(ctx, relativePath, opts)
	if err != nil {
		return nil, err
	}
	return &writerCloser{writer, bucket}, nil
}

type UploadFunc func() (io.Reader, *blob.Attributes, error)

func FileUpload(file string, attr *blob.Attributes) UploadFunc {
	return func() (io.Reader, *blob.Attributes, error) {
		reader, err := os.Open(file)
		if err != nil {
			return nil, nil, err
		}
		return reader, attr, nil
	}
}

func DataUpload(reader io.Reader, attr *blob.Attributes) UploadFunc {
	return func() (io.Reader, *blob.Attributes, error) {
		return reader, attr, nil
	}
}

func (o *opener) Upload(ctx context.Context, uploads map[string]UploadFunc) error {
	errCh := make(chan error, len(uploads))
	group := &sync.WaitGroup{}
	group.Add(len(uploads))
	for dest, upload := range uploads {
		log := logrus.WithField("dest", dest)
		log.Infof("Queued %s for upload", dest)
		go func(f UploadFunc, dest string, log *logrus.Entry) {
			defer group.Done()
			reader, attr, err := f()
			if err != nil {
				errCh <- err
			}

			writer, err := o.Writer(ctx, dest, convertAttributesToWriterOptions(attr))
			if err != nil {
				errCh <- err
				return
			}
			_, copyErr := io.Copy(writer, reader)
			if copyErr != nil {
				copyErr = fmt.Errorf("copy error: %v", copyErr)
			}
			closeErr := writer.Close()
			if closeErr != nil {
				closeErr = fmt.Errorf("writer close error: %v", closeErr)
			}
			err = errorutil.NewAggregate(copyErr, closeErr)
			if err != nil {
				errCh <- err
			} else {
				log.Info("Finished upload")
			}
		}(upload, dest, log)
	}
	group.Wait()
	close(errCh)
	if len(errCh) != 0 {
		var uploadErrors []error
		for err := range errCh {
			uploadErrors = append(uploadErrors, err)
		}
		return fmt.Errorf("encountered errors during upload: %v", uploadErrors)
	}
	return nil
}

func convertAttributesToWriterOptions(a *blob.Attributes) *blob.WriterOptions {
	if a == nil {
		return nil
	}
	return &blob.WriterOptions{
		CacheControl:       a.CacheControl,
		ContentDisposition: a.ContentDisposition,
		ContentEncoding:    a.ContentEncoding,
		ContentLanguage:    a.ContentLanguage,
		ContentType:        a.ContentType,
		ContentMD5:         a.MD5,
		Metadata:           a.Metadata,
	}
}

func (o *opener) GetGCSClient(ctx context.Context) (*storage.Client, error) {
	bucket, err := o.getBucket(ctx, "gs://give-me-the-client")
	if err != nil {
		return nil, err
	}
	var gcsClient *storage.Client
	if bucket.As(&gcsClient) {
		return gcsClient, nil
	}
	return nil, fmt.Errorf("unable to access storage.Client through Bucket.As")
}

func (o *opener) getStorageProvider(storagePath string) (StorageProvider, error) {
	for spName, sp := range storageProviderPathIdentifiers {
		if strings.HasPrefix(storagePath, sp.StoragePrefix+sp.StorageSeparator) {
			return o.storageProviders[spName], nil
		}
	}
	return o.storageProviders[DefaultStorageProviderName], nil
}

func (o *opener) getBucket(ctx context.Context, path string) (*blob.Bucket, error) {
	sp, err := o.getStorageProvider(path)
	if err != nil {
		return nil, fmt.Errorf("could not get bucket: %w", err)
	}
	bucket, _, err := ParseStoragePath(path)
	if err != nil {
		return nil, fmt.Errorf("could not get bucket: %w", err)
	}
	return sp.GetBucket(ctx, bucket)
}

// IsNotExist will return true if the error is because the object does not exist.
func IsNotExist(err error) bool {
	return gcerrors.Code(err) == gcerrors.NotFound
}

// LogClose will attempt a close an log any error
func LogClose(c io.Closer) {
	if err := c.Close(); err != nil {
		logrus.WithError(err).Error("Failed to close")
	}
}
