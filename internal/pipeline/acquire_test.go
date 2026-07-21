package pipeline

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSBOM drops content into a temp file and returns its path.
func writeSBOM(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A minimal CycloneDX doc at a given spec version, one maven component.
func cdxDoc(specVersion string) string {
	return `{
  "bomFormat": "CycloneDX",
  "specVersion": "` + specVersion + `",
  "version": 1,
  "components": [
    {"type": "library", "name": "com.google.guava/guava", "version": "33.0.0-jre",
     "purl": "pkg:maven/com.google.guava/guava@33.0.0-jre"}
  ]
}`
}

func TestAcquireSBOMRejectsBelow16(t *testing.T) {
	var warn bytes.Buffer
	_, err := acquireSBOM(writeSBOM(t, cdxDoc("1.5")), &warn)
	if err == nil || !strings.Contains(err.Error(), "below the 1.6 minimum") {
		t.Fatalf("want below-1.6 rejection, got %v", err)
	}
}

func TestAcquireSBOMAccepts17WithWarnAndDownconverts(t *testing.T) {
	var warn bytes.Buffer
	out, err := acquireSBOM(writeSBOM(t, cdxDoc("1.7")), &warn)
	if err != nil {
		t.Fatalf("acquireSBOM: %v", err)
	}
	if !strings.Contains(warn.String(), "down-converting to 1.6") {
		t.Errorf("want stderr 1.7 warning, got %q", warn.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if got["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", got["specVersion"])
	}
}

func TestAcquireSBOMAccepts16(t *testing.T) {
	var warn bytes.Buffer
	out, err := acquireSBOM(writeSBOM(t, cdxDoc("1.6")), &warn)
	if err != nil {
		t.Fatalf("acquireSBOM: %v", err)
	}
	if warn.Len() != 0 {
		t.Errorf("unexpected warning for 1.6 input: %q", warn.String())
	}
	if !bytes.Contains(out, []byte(`"1.6"`)) {
		t.Errorf("output missing specVersion 1.6:\n%s", out)
	}
}

func TestAcquireSBOMRejectsMalformed(t *testing.T) {
	var warn bytes.Buffer
	_, err := acquireSBOM(writeSBOM(t, "this is not a cyclonedx document"), &warn)
	if err == nil || !strings.Contains(err.Error(), "decode --sbom") {
		t.Fatalf("want decode error, got %v", err)
	}
}

// Well-formed JSON that isn't CycloneDX (e.g. an SPDX doc) decodes cleanly but must
// still be rejected — with a clear "not a CycloneDX" message, not a spec-version error.
func TestAcquireSBOMRejectsValidJSONNonCycloneDX(t *testing.T) {
	var warn bytes.Buffer
	_, err := acquireSBOM(writeSBOM(t, `{"spdxVersion":"SPDX-2.3","name":"x"}`), &warn)
	if err == nil || !strings.Contains(err.Error(), "not a CycloneDX") {
		t.Fatalf("want 'not a CycloneDX' error, got %v", err)
	}
}
