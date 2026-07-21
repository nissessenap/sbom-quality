package pipeline

import (
	"encoding/json"
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
