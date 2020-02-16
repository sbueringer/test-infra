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

package util

import (
	"fmt"
	"path"
	"strings"

	"k8s.io/test-infra/pkg/io/v2/providers"
)

func ParseStoragePath(identifiers providers.StorageProviderPathIdentifiers, storagePath string) (bucket, relativePath string, err error) {
	if !strings.HasPrefix(storagePath, identifiers.StoragePrefix+identifiers.StorageSeparator) {
		return "", "", fmt.Errorf("path is not a valid %s path: %s", identifiers.StoragePrefix, storagePath)
	}
	storagePath = strings.TrimPrefix(storagePath, identifiers.StoragePrefix+identifiers.StorageSeparator)

	pathSplit := strings.Split(storagePath, "/")
	if len(pathSplit) < 2 {
		return "", "", fmt.Errorf("path is not a valid %s path: %s", identifiers.StoragePrefix, storagePath)
	}
	return pathSplit[0], path.Join(pathSplit[1:]...), nil
}
