package initdata

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	pkginitdata "github.com/confidential-devhub/cococtl/pkg/initdata"
)

func makeRawInitdataFile(t *testing.T, dir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "cfg.toml")
	_ = os.WriteFile(cfgPath, []byte("trustee_server = \"http://kbs.test.svc:8080\"\nruntime_class = \"kata-cc\"\n"), 0600)
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	raw, err := pkginitdata.GenerateRaw(cfg, "", nil)
	if err != nil {
		t.Fatalf("GenerateRaw: %v", err)
	}
	path := filepath.Join(dir, "initdata.toml")
	_ = os.WriteFile(path, raw, 0600)
	return path
}

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
	dir := t.TempDir()
	tomlPath := makeRawInitdataFile(t, dir)
	dumpFile = tomlPath
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
	dir := t.TempDir()
	tomlPath := makeRawInitdataFile(t, dir)
	dumpFile = tomlPath
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
