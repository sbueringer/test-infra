package providers_test

import (
	"k8s.io/test-infra/pkg/io/v2/providers"
	"testing"
)


func TestParseStoragePath(t *testing.T) {
	type args struct {
		storagePath string
	}
	tests := []struct {
		name                string
		args                args
		wantStorageProvider string
		wantBucket          string
		wantRelativePath    string
		wantErr             bool
	}{
		{
			name:                "parse file path without file:// prefix",
			args:                args{storagePath: "/tmp/local/test.md"},
			wantStorageProvider: "file",
			wantBucket:          "/tmp/local/",
			wantRelativePath:    "test.md",
			wantErr:             false,
		},
		{
			name:                "parse file path with file:// prefix",
			args:                args{storagePath: "file:///tmp/local/test.md"},
			wantStorageProvider: "file",
			wantBucket:          "/tmp/local/",
			wantRelativePath:    "test.md",
			wantErr:             false,
		},
		{
			name:                "parse file path with file:// prefix",
			args:                args{storagePath: "file:///tmp/"},
			wantStorageProvider: "file",
			wantBucket:          "/tmp/",
			wantRelativePath:    "",
			wantErr:             false,
		},
		{
			name:                "parse s3 path",
			args:                args{storagePath: "s3://prow-artifacts/test"},
			wantStorageProvider: "s3",
			wantBucket:          "prow-artifacts",
			wantRelativePath:    "test",
			wantErr:             false,
		},
		{
			name:                "parse s3 deep path",
			args:                args{storagePath: "s3://prow-artifacts/pr-logs/test"},
			wantStorageProvider: "s3",
			wantBucket:          "prow-artifacts",
			wantRelativePath:    "pr-logs/test",
			wantErr:             false,
		},
		{
			name:                "parse gcs path",
			args:                args{storagePath: "gcs://prow-artifacts/pr-logs/bazel-build/test.log"},
			wantStorageProvider: "gs",
			wantBucket:          "prow-artifacts",
			wantRelativePath:    "pr-logs/bazel-build/test.log",
			wantErr:             false,
		},
		{
			name:                "parse gs path",
			args:                args{storagePath: "gs://prow-artifacts/pr-logs/bazel-build/test.log"},
			wantStorageProvider: "gs",
			wantBucket:          "prow-artifacts",
			wantRelativePath:    "pr-logs/bazel-build/test.log",
			wantErr:             false,
		},
		{
			name:                "parse gs short path",
			args:                args{storagePath: "gs://prow-artifacts"},
			wantStorageProvider: "gs",
			wantBucket:          "prow-artifacts",
			wantRelativePath:    "",
			wantErr:             false,
		},
		{
			name:                "parse gs to short path fails",
			args:                args{storagePath: "gs://"},
			wantErr:             true,
		},
		{
			name:                "parse unknown prefix path fails",
			args:                args{storagePath: "s4://prow-artifacts/pr-logs/bazel-build/test.log"},
			wantErr:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStorageProvider, gotBucket, gotRelativePath, err := providers.ParseStoragePath(tt.args.storagePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseStoragePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotStorageProvider != tt.wantStorageProvider {
				t.Errorf("ParseStoragePath() gotStorageProvider = %v, want %v", gotStorageProvider, tt.wantStorageProvider)
			}
			if gotBucket != tt.wantBucket {
				t.Errorf("ParseStoragePath() gotBucket = %v, want %v", gotBucket, tt.wantBucket)
			}
			if gotRelativePath != tt.wantRelativePath {
				t.Errorf("ParseStoragePath() gotRelativePath = %v, want %v", gotRelativePath, tt.wantRelativePath)
			}
		})
	}
}