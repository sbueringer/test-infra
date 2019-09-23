package providerimports

// We need to empty import all enabled providers so they will be linked
import (
	_ "k8s.io/test-infra/pkg/io/file"
	_ "k8s.io/test-infra/pkg/io/gcs"
	_ "k8s.io/test-infra/pkg/io/s3"
)
