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
	"os"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"

	"k8s.io/test-infra/pkg/io/v2/providers"
	"k8s.io/test-infra/prow/errorutil"
)

// Aliases to types in the standard library
type (
	ReadCloser  = io.ReadCloser
	WriteCloser = io.WriteCloser
)

// Opener has methods to read, write paths, create signed URLs,...
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

	// Workaround to retrieve the storageClient for prow/spyglass/testgrid.go because it calls
	// github.com/GoogleCloudPlatform/testgrid/config.Read() which only works with GCS storage client right now
	GetGCSClient(ctx context.Context) (*storage.Client, error)
}

type opener struct {
	credentials []byte
}

// NewOpener returns an opener that can read GCS, S3 and local paths.
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
		credentials: credentials,
	}, nil
}

func (o *opener) getBucket(ctx context.Context, path string) (*blob.Bucket, string, error) {
	sp, err := providers.GetStorageProvider(path)
	if err != nil {
		return nil, "", fmt.Errorf("could not get bucket: %w", err)
	}
	bucketName, relativePath, err := providers.ParseStoragePath(path)
	if err != nil {
		return nil, "", fmt.Errorf("could not get bucket: %w", err)
	}
	bucket, err := sp.GetBucket(ctx, o.credentials, bucketName)
	if err != nil {
		return nil, "", err
	}
	return bucket, relativePath, nil
}

func (o *opener) Reader(ctx context.Context, path string, opts *blob.ReaderOptions) (io.ReadCloser, error) {
	bucket, relativePath, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	reader, err := bucket.NewReader(ctx, relativePath, opts)
	if err != nil {
		return nil, err
	}
	return readerCloser{reader, bucket}, nil
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

func (o *opener) RangeReader(ctx context.Context, path string, offset, length int64, opts *blob.ReaderOptions) (io.ReadCloser, error) {
	bucket, relativePath, err := o.getBucket(ctx, path)
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
	b, relativePath, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	return b.ReadAll(ctx, relativePath)
}

func (o *opener) Attributes(ctx context.Context, path string) (*blob.Attributes, error) {
	b, relativePath, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}

	return b.Attributes(ctx, relativePath)
}

func (o *opener) SignedURL(ctx context.Context, path string, opts *blob.SignedURLOptions) (string, error) {
	sp, err := providers.GetStorageProvider(path)
	if err != nil {
		return "", nil
	}
	bucket, relativePath, err := providers.ParseStoragePath(path)
	if err != nil {
		return "", err
	}
	return sp.SignedURL(ctx, o.credentials, bucket, relativePath, opts)
}

// Lists all paths with given path. If matchFuncs are given, all must match so that the obj
// is included in the result
func (o *opener) ListSubPaths(ctx context.Context, path string, matchFns ...func(*blob.ListObject) bool) ([]string, error) {
	paths := []string{}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	_, relativePath, err := providers.ParseStoragePath(path)
	if err != nil {
		return nil, err
	}
	pathPrefix := strings.TrimSuffix(path, relativePath+"/")

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
	bucket, relativePath, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	q := &blob.ListOptions{
		Prefix:    relativePath + "/",
		Delimiter: "/",
	}

	return bucket.List(q), nil
}

func (o *opener) ListSubDirs(ctx context.Context, path string) ([]string, error) {
	return o.ListSubPaths(ctx, path, func(obj *blob.ListObject) bool {
		return obj.IsDir
	})
}

// Writer returns a writer that overwrites the path.
func (o *opener) Writer(ctx context.Context, path string, opts *blob.WriterOptions) (io.WriteCloser, error) {
	bucket, relativePath, err := o.getBucket(ctx, path)
	if err != nil {
		return nil, err
	}
	writer, err := bucket.NewWriter(ctx, relativePath, opts)
	if err != nil {
		return nil, err
	}
	return &writerCloser{writer, bucket}, nil
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
	bucket, _, err := o.getBucket(ctx, "gs://give-me-the-client")
	if err != nil {
		return nil, err
	}
	var gcsClient *storage.Client
	if bucket.As(&gcsClient) {
		return gcsClient, nil
	}
	return nil, fmt.Errorf("unable to access storage.Client through Bucket.As")
}

// ErrNotFoundTest can be used for unit tests to simulate NotFound errors.
// This is required because gocloud doesn't exposes its errors.
var ErrNotFoundTest = fmt.Errorf("not found error which should only be used in tests")

// IsNotExist will return true if the error is because the object does not exist.
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

// TODO: not sure if it's worth having a separate method, but for now it's easier
// to track where we're joining storagePath (and where the regular path.Join doesn't
// work because it removes one of the slashes in e.g. s3://)
func JoinStoragePath(elem ...string) string {
	return strings.Join(elem, "/")
}
