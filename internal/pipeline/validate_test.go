package pipeline

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// The real sbom-utility JSON report for a component carrying an SPDX id its
// embedded list doesn't know (Artistic-dist): the actionable enum error plus the
// oneOf cascade it triggers. staleLicenseIDs must pick out only the id.
func TestStaleLicenseIDs(t *testing.T) {
	const report = `[
	  {"type":"number_one_of","field":"components.128.licenses","value":[]},
	  {"type":"enum","field":"components.128.licenses.18.license.id","value":"Artistic-dist"},
	  {"type":"enum","field":"metadata.component.licenses.0.license.id","value":"Some-New-3.0"},
	  {"type":"enum","field":"components.1.hashes.0.alg","value":"BOGUS"}
	]`
	var errs []schemaError
	if err := json.Unmarshal([]byte(report), &errs); err != nil {
		t.Fatal(err)
	}
	stale := staleLicenseIDs(errs)
	if len(stale) != 2 || !stale["Artistic-dist"] || !stale["Some-New-3.0"] {
		t.Fatalf("want {Artistic-dist, Some-New-3.0}, got %v", stale)
	}
	if stale["BOGUS"] {
		t.Fatal("must not demote a non-license enum error (hashes.alg)")
	}
}

// demoteLicenseIDs moves a stale id to name across primary + nested components,
// leaves valid ids and non-stale entries untouched.
func TestDemoteLicenseIDs(t *testing.T) {
	lics := func(id string) *cdx.Licenses {
		return &cdx.Licenses{{License: &cdx.License{ID: id, Acknowledgement: cdx.LicenseAcknowledgementDeclared}}}
	}
	nested := cdx.Component{Type: cdx.ComponentTypeLibrary, Licenses: lics("Artistic-dist")}
	bom := &cdx.BOM{
		Metadata: &cdx.Metadata{Component: &cdx.Component{Licenses: lics("Artistic-dist")}},
		Components: &[]cdx.Component{
			{Type: cdx.ComponentTypeLibrary, Licenses: lics("MIT")},
			{Type: cdx.ComponentTypeLibrary, Licenses: lics("Artistic-dist"), Components: &[]cdx.Component{nested}},
		},
	}

	demoteLicenseIDs(bom, map[string]bool{"Artistic-dist": true})

	// primary demoted, acknowledgement preserved
	got := (*bom.Metadata.Component.Licenses)[0].License
	if got.ID != "" || got.Name != "Artistic-dist" {
		t.Fatalf("primary: want name=Artistic-dist id empty, got id=%q name=%q", got.ID, got.Name)
	}
	if got.Acknowledgement != cdx.LicenseAcknowledgementDeclared {
		t.Fatal("primary: acknowledgement must survive demotion")
	}
	// valid id untouched
	if mit := (*(*bom.Components)[0].Licenses)[0].License; mit.ID != "MIT" || mit.Name != "" {
		t.Fatalf("valid id must stay in id, got id=%q name=%q", mit.ID, mit.Name)
	}
	// component + its nested child both demoted
	if c := (*(*bom.Components)[1].Licenses)[0].License; c.ID != "" || c.Name != "Artistic-dist" {
		t.Fatalf("component: want demoted, got id=%q name=%q", c.ID, c.Name)
	}
	if n := (*(*(*bom.Components)[1].Components)[0].Licenses)[0].License; n.ID != "" || n.Name != "Artistic-dist" {
		t.Fatalf("nested: want demoted, got id=%q name=%q", n.ID, n.Name)
	}
}

// validate() wires validateReport -> demote -> re-validate and RETURNS the repaired
// bytes; run.go relies on that return (sbom, err = validate(sbom)). Exercise the whole
// flow against a fake sbom-utility so a revert of that wiring — or a demote scope that
// misses metadata.licenses (High-2) — fails a test instead of silently shipping an
// un-repaired doc.
func TestValidateRepairsStaleLicenseID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake sbom-utility is a POSIX shell script")
	}
	// Rejects any document still carrying `"id":"Artistic-dist"`, accepts everything else.
	installFakeSBOMUtility(t)

	lics := func() *cdx.Licenses { return &cdx.Licenses{{License: &cdx.License{ID: "Artistic-dist"}}} }
	in, err := encode16(&cdx.BOM{
		Metadata: &cdx.Metadata{
			Licenses:  lics(),                           // High-2: document-level metadata.licenses
			Component: &cdx.Component{Licenses: lics()}, // primary component
		},
		Components: &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, Licenses: lics()}},
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := validate(in)
	if err != nil {
		t.Fatalf("validate should repair the stale id, got: %v", err)
	}
	if bytes.Contains(bytes.ReplaceAll(out, []byte(" "), nil), []byte(`"id":"Artistic-dist"`)) {
		t.Fatal("stale id survived in output — validate returned an un-repaired doc")
	}
	if !bytes.Contains(out, []byte("Artistic-dist")) {
		t.Fatal("license value lost entirely — demote must preserve it as a free-form name")
	}
}

// installFakeSBOMUtility puts a script named sbom-utility at the front of PATH. It
// mimics the contract validateReport depends on: exit non-zero with a JSON error array
// on stdout while the doc still carries a stale id, exit 0 once it's clean.
func installFakeSBOMUtility(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/usr/bin/env bash
file=""; prev=""
for a in "$@"; do [ "$prev" = "--input-file" ] && file="$a"; prev="$a"; done
if tr -d ' \n\t' < "$file" | grep -q '"id":"Artistic-dist"'; then
  echo '[{"type":"enum","field":"metadata.licenses.0.license.id","value":"Artistic-dist"}]'
  exit 1
fi
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "sbom-utility"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
