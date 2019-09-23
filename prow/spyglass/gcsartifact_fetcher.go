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

package spyglass

import (
	"context"
	"errors"
	"fmt"
	"gocloud.dev/blob"
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	prowio "k8s.io/test-infra/pkg/io"
	"k8s.io/test-infra/prow/spyglass/lenses"
)

var (
	// ErrCannotParseSource is returned by newGCSJobSource when an incorrectly formatted source string is passed
	ErrCannotParseSource = errors.New("could not create job source from provided source")
)

// GCSArtifactFetcher contains information used for fetching artifacts from GCS
type GCSArtifactFetcher struct {
	opener       prowio.Opener
}

// NewGCSArtifactFetcher creates a new ArtifactFetcher with a real GCS Client
func NewGCSArtifactFetcher(opener prowio.Opener) *GCSArtifactFetcher {
	return &GCSArtifactFetcher{
		opener:       opener,
	}
}

// Artifacts lists all artifacts available for the given job source
func (af *GCSArtifactFetcher) artifacts(key string) ([]string, error) {
	listStart := time.Now()
	artifacts := []string{}

	objIter, err := af.opener.ListSubPathsIter(context.TODO(), key)
	if err != nil {
		return artifacts, err
	}

	wait := []time.Duration{16, 32, 64, 128, 256, 256, 512, 512}
	for i := 0; ; {
		oAttrs, err := objIter.Next(context.Background())
		if err == io.EOF {
			break
		}
		if oAttrs == nil {
			break
		}
		if err != nil {
			logrus.WithFields(logrus.Fields{"jobPrefix":key}).WithError(err).Error("Error accessing Blob Store artifact.")
			if i >= len(wait) {
				return artifacts, fmt.Errorf("timed out: error accessing artifact: %v", err)
			}
			time.Sleep((wait[i] + time.Duration(rand.Intn(10))) * time.Millisecond)
			i++
			continue
		}
		keySplit := strings.Split(oAttrs.Key, "/")
		name := keySplit[len(keySplit)-1]
		artifacts = append(artifacts, name)
		i = 0
	}
	logrus.WithField("duration", time.Since(listStart).String()).Infof("Listed %d artifacts.", len(artifacts))
	return artifacts, nil
}

type gcsArtifactHandle struct {
	prowio.Opener
	ObjName string
}

func (h *gcsArtifactHandle) NewReader(ctx context.Context) (io.ReadCloser, error) {
	return h.Opener.Reader(ctx, h.ObjName,nil)
}

func (h *gcsArtifactHandle) NewRangeReader(ctx context.Context, offset, length int64) (io.ReadCloser, error) {
	return h.Opener.RangeReader(ctx, h.ObjName, offset, length, nil)
}

func (h *gcsArtifactHandle) Attrs(ctx context.Context) (*blob.Attributes, error) {
	return h.Opener.Attributes(ctx, h.ObjName)
}

// Artifact constructs a GCS artifact from the given GCS bucket and key. Uses the golang GCS library
// to get read handles. If the artifactName is not a valid key in the bucket a handle will still be
// constructed and returned, but all read operations will fail (dictated by behavior of golang GCS lib).
func (af *GCSArtifactFetcher) artifact(key string, artifactName string, sizeLimit int64) (lenses.Artifact, error) {
	objName := prowio.JoinStoragePath(key, artifactName)
	obj := &gcsArtifactHandle{af.opener, objName}
	signedURL, err := af.opener.SignedURL(context.TODO(), objName, &blob.SignedURLOptions{
		Method:         "GET",
		Expiry:        10 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	return NewGCSArtifact(context.Background(), obj, signedURL, artifactName, sizeLimit), nil
}
