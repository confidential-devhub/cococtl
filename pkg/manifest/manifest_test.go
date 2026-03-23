package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAndCleanPath(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr string // substring; empty means success
	}{
		{
			name: "relative path inside cwd",
			path: "manifest.go",
		},
		{
			name: "absolute path without traversal",
			path: filepath.Join(cwd, "manifest.go"),
		},
		{
			name: "nested relative path inside cwd",
			path: filepath.Join("testdata", "foo.yaml"),
		},
		{
			// Goes two levels up from pkg/manifest into cmd/ — outside cwd.
			name:    "relative path that escapes cwd",
			path:    "../../cmd/apply.go",
			wantErr: "escapes current directory",
		},
		{
			// String concatenation preserves the literal ".." so Contains fires.
			// filepath.Join would resolve it away before the check.
			name:    "absolute path with literal double-dot segment",
			path:    cwd + "/../../../etc/passwd",
			wantErr: "contains directory traversal",
		},
		{
			// Sibling directory shares the cwd string as a prefix but is outside it.
			// Without the filepath.Separator suffix on the HasPrefix check this would
			// pass incorrectly: cwd="…/manifest", sibling="…/manifest-evil" satisfies
			// HasPrefix(sibling, cwd) but NOT HasPrefix(sibling, cwd+"/").
			name:    "relative prefix-collision: sibling dir shares cwd name prefix",
			path:    "../manifest-evil/secret.yaml",
			wantErr: "escapes current directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAndCleanPath(tt.path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (result %q)", tt.wantErr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !filepath.IsAbs(got) {
				t.Errorf("expected absolute path, got %q", got)
			}
		})
	}
}
