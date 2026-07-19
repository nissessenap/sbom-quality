package pipeline

import (
	"bytes"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// patchBOM is a fixture lacking every field the four patches fill: an expression-form
// license, no acknowledgement, no compositions, and a wrapper component with no
// supplier/license. The doc supplier + primary license are what the back-fills copy.
func patchBOM() *cdx.BOM {
	return &cdx.BOM{
		Metadata: &cdx.Metadata{
			Supplier: &cdx.OrganizationalEntity{Name: "ACME"},
			Component: &cdx.Component{
				Type:     cdx.ComponentTypeApplication,
				Name:     "example.com/app",
				BOMRef:   "root",
				Licenses: &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}},
			},
		},
		Dependencies: &[]cdx.Dependency{{Ref: "root"}},
		Components: &[]cdx.Component{
			{
				Type:     cdx.ComponentTypeLibrary, // wrapper type, missing supplier + license
				Name:     "example.com/dep",
				BOMRef:   "dep",
				Licenses: &cdx.Licenses{{Expression: "(MIT)"}},
			},
		},
	}
}

func TestPatchLicenseAcknowledgementAndUnwrap(t *testing.T) {
	bom := patchBOM()
	applyQualityPatch(bom)

	// primary component: existing license gains acknowledgement:declared.
	if ack := (*bom.Metadata.Component.Licenses)[0].License.Acknowledgement; ack != cdx.LicenseAcknowledgementDeclared {
		t.Errorf("primary license acknowledgement = %q, want declared", ack)
	}
	// dep component: expression "(MIT)" unwrapped to a declared license.name.
	lc := (*(*bom.Components)[0].Licenses)[0]
	if lc.Expression != "" {
		t.Errorf("expression not unwrapped: %q", lc.Expression)
	}
	if lc.License == nil || lc.License.Name != "MIT" {
		t.Fatalf("unwrapped license = %+v, want name MIT", lc.License)
	}
	if lc.License.Acknowledgement != cdx.LicenseAcknowledgementDeclared {
		t.Errorf("unwrapped license acknowledgement = %q, want declared", lc.License.Acknowledgement)
	}
}

func TestPatchCompositionsComplete(t *testing.T) {
	bom := patchBOM()
	applyQualityPatch(bom)

	if bom.Compositions == nil || len(*bom.Compositions) == 0 {
		t.Fatal("no compositions declared")
	}
	if (*bom.Compositions)[0].Aggregate != cdx.CompositionAggregateComplete {
		t.Errorf("aggregate = %q, want complete", (*bom.Compositions)[0].Aggregate)
	}
}

func TestPatchWrapperSupplierBackfill(t *testing.T) {
	bom := patchBOM()
	applyQualityPatch(bom)

	if s := (*bom.Components)[0].Supplier; s == nil || s.Name != "ACME" {
		t.Errorf("wrapper supplier = %+v, want our own ACME back-filled", s)
	}
	if s := bom.Metadata.Component.Supplier; s == nil || s.Name != "ACME" {
		t.Errorf("primary supplier = %+v, want our own ACME back-filled", s)
	}
}

func TestPatchWrapperLicenseBackfill(t *testing.T) {
	bom := patchBOM()
	applyQualityPatch(bom)

	// the dep had its own (unwrapped) license — that must survive, not be overwritten.
	if got := (*(*bom.Components)[0].Licenses)[0].License.Name; got != "MIT" {
		t.Errorf("wrapper license overwritten: got %q, want its own MIT preserved", got)
	}

	// a wrapper genuinely lacking a license gets the primary license copied.
	bom = patchBOM()
	(*bom.Components)[0].Licenses = nil
	applyQualityPatch(bom)
	lics := (*bom.Components)[0].Licenses
	if lics == nil || len(*lics) == 0 || (*lics)[0].License.ID != "Apache-2.0" {
		t.Errorf("wrapper license = %+v, want primary Apache-2.0 back-filled", lics)
	}
}

// back-filled supplier/license must be bom-ref-free copies, else reusing a source
// bom-ref across components would fail sbom-utility validate (CDX bom-ref uniqueness).
func TestPatchBackfillClearsBOMRefs(t *testing.T) {
	bom := patchBOM()
	bom.Metadata.Supplier.BOMRef = "supplier-ref"
	(*bom.Metadata.Component.Licenses)[0].License.BOMRef = "license-ref"
	(*bom.Components)[0].Licenses = nil // force license back-fill
	applyQualityPatch(bom)

	wrapper := (*bom.Components)[0]
	if wrapper.Supplier.BOMRef != "" {
		t.Errorf("back-filled supplier bom-ref = %q, want cleared", wrapper.Supplier.BOMRef)
	}
	if wrapper.Supplier == bom.Metadata.Supplier {
		t.Error("back-filled supplier is the shared source pointer, want an independent copy")
	}
	if lic := (*wrapper.Licenses)[0].License; lic.BOMRef != "" {
		t.Errorf("back-filled license bom-ref = %q, want cleared", lic.BOMRef)
	}
}

// qualityPatch round-trips through 1.6 JSON: decode, apply, re-encode.
func TestQualityPatchRoundTripEncodes16(t *testing.T) {
	in := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,` +
		`"metadata":{"supplier":{"name":"ACME"},"component":{"type":"application","name":"app","bom-ref":"root",` +
		`"licenses":[{"expression":"(MIT)"}]}}}`)
	out, err := qualityPatch(in)
	if err != nil {
		t.Fatalf("qualityPatch: %v", err)
	}
	if !bytes.Contains(out, []byte(`"1.6"`)) {
		t.Errorf("output not 1.6:\n%s", out)
	}
	if !bytes.Contains(out, []byte(`"declared"`)) {
		t.Errorf("acknowledgement not in output:\n%s", out)
	}
	if !bytes.Contains(out, []byte(`"complete"`)) {
		t.Errorf("compositions complete not in output:\n%s", out)
	}
}
