package initdata

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()
	return buf.String()
}

func TestRunDump_Encoded(t *testing.T) {
	dumpFile = "testdata/valid.toml"
	dumpRaw = false
	defer func() { dumpFile = ""; dumpRaw = false }()

	var runErr error
	output := captureStdout(t, func() { runErr = runDump(nil, nil) })
	if runErr != nil {
		t.Fatalf("runDump() error: %v", runErr)
	}
	trimmed := strings.TrimSpace(output)
	if _, err := base64.StdEncoding.DecodeString(trimmed); err != nil {
		t.Errorf("output is not valid base64: %v", err)
	}
}

func TestRunDump_Raw(t *testing.T) {
	dumpFile = "testdata/valid.toml"
	dumpRaw = true
	defer func() { dumpFile = ""; dumpRaw = false }()

	var runErr error
	output := captureStdout(t, func() { runErr = runDump(nil, nil) })
	if runErr != nil {
		t.Fatalf("runDump --raw error: %v", runErr)
	}
	var id pkginitdata.InitData
	if err := toml.Unmarshal([]byte(output), &id); err != nil {
		t.Fatalf("--raw output is not valid TOML: %v", err)
	}
	if id.Version != pkginitdata.InitDataVersion {
		t.Errorf("version = %q, want %q", id.Version, pkginitdata.InitDataVersion)
	}
}

func TestRunDump_MissingFile(t *testing.T) {
	dumpFile = "/nonexistent/initdata.toml"
	dumpRaw = false
	defer func() { dumpFile = "" }()
	if err := runDump(nil, nil); err == nil {
		t.Fatal("expected error for missing file")
	}
}
