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
	"gocloud.dev/blob"
)

func ExampleReadModifyWrite() {

	ctx := context.Background()
	path := "gs://path/test"

	opener, _ := NewOpener(ctx, "credentials")

	// Retrieve attributes
	attrs, _ := opener.Attributes(ctx, path)

	// Let's add a condition for atomic read-modify-write if we're using GCS
	opts := &blob.WriterOptions{}
	var oa storage.ObjectAttrs
	if attrs.As(&oa) {
		opts.BeforeWrite = func(asFunc func(interface{}) bool) error {
			var objp **storage.ObjectHandle
			if !asFunc(&objp) {
				return fmt.Errorf("Writer.As failed to get ObjectHandle")
			}
			// Replace the ObjectHandle with a new one that adds Conditions.
			*objp = (*objp).If(storage.Conditions{GenerationMatch: oa.Generation})
			return nil
		}
	}

	writer, _ := opener.Writer(ctx, "gs://path/test", opts)

	writer.Write([]byte("content"))
}