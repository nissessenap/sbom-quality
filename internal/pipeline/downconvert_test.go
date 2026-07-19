package pipeline

import (
	"bytes"
	"encoding/json"
	"testing"
)

// A minimal trivy-shaped CycloneDX 1.7 document with one Go component carrying a
// license and a PURL. The down-convert must retain every component field and only
// change the spec version.
const bom17 = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "metadata": {
    "component": {
      "type": "container",
      "name": "example.com/app",
      "bom-ref": "root"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:golang/github.com/foo/bar@v1.2.3",
      "name": "github.com/foo/bar",
      "version": "v1.2.3",
      "purl": "pkg:golang/github.com/foo/bar@v1.2.3",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ]
}`

func TestDownConvertTo16(t *testing.T) {
	out, err := downConvertTo16([]byte(bom17))
	if err != nil {
		t.Fatalf("downConvertTo16: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if got["specVersion"] != "1.6" {
		t.Fatalf("specVersion = %v, want 1.6", got["specVersion"])
	}

	// No data corruption: the component and its fields survive the round-trip.
	comps, ok := got["components"].([]any)
	if !ok || len(comps) != 1 {
		t.Fatalf("components = %v, want exactly 1", got["components"])
	}
	comp := comps[0].(map[string]any)
	for field, want := range map[string]string{
		"name":    "github.com/foo/bar",
		"version": "v1.2.3",
		"purl":    "pkg:golang/github.com/foo/bar@v1.2.3",
		"bom-ref": "pkg:golang/github.com/foo/bar@v1.2.3",
	} {
		if comp[field] != want {
			t.Errorf("component %s = %v, want %v", field, comp[field], want)
		}
	}
	if !bytes.Contains(out, []byte(`"MIT"`)) {
		t.Errorf("license MIT missing from output:\n%s", out)
	}
}
