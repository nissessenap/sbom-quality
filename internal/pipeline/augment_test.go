package pipeline

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// baseBOM returns a fixture carrying generator-supplied values, so tests can prove
// a flag/autodetect overrides them and an absent one leaves them intact.
func baseBOM() *cdx.BOM {
	return &cdx.BOM{
		Metadata: &cdx.Metadata{
			Supplier:     &cdx.OrganizationalEntity{Name: "generator-supplier"},
			Authors:      &[]cdx.OrganizationalContact{{Name: "generator-author"}},
			Manufacturer: &cdx.OrganizationalEntity{Name: "generator-mfr"},
			Lifecycles:   &[]cdx.Lifecycle{{Phase: cdx.LifecyclePhaseOperations}},
			Component: &cdx.Component{
				Type:     cdx.ComponentTypeApplication,
				Name:     "example.com/app",
				BOMRef:   "root",
				Licenses: &cdx.Licenses{{License: &cdx.License{Name: "generator-license"}}},
				ExternalReferences: &[]cdx.ExternalReference{
					{Type: cdx.ERTypeVCS, URL: "https://generator.example/repo"},
				},
			},
		},
	}
}

func TestAugmentFlagBeatsGenerator(t *testing.T) {
	bom := baseBOM()
	applyAugment(bom, Config{SupplierName: "flag-supplier"}, vcsInfo{})

	if got := bom.Metadata.Supplier.Name; got != "flag-supplier" {
		t.Errorf("supplier = %q, want flag-supplier (flag beats generator)", got)
	}
}

func TestAugmentAbsentFlagKeepsGenerator(t *testing.T) {
	bom := baseBOM()
	applyAugment(bom, Config{}, vcsInfo{}) // no flags, no autodetect

	md := bom.Metadata
	if md.Supplier.Name != "generator-supplier" {
		t.Errorf("supplier = %q, want generator-supplier preserved", md.Supplier.Name)
	}
	if (*md.Authors)[0].Name != "generator-author" {
		t.Errorf("authors = %+v, want generator value preserved", md.Authors)
	}
	if md.Manufacturer.Name != "generator-mfr" {
		t.Errorf("manufacturer = %q, want generator value preserved", md.Manufacturer.Name)
	}
	if (*md.Lifecycles)[0].Phase != cdx.LifecyclePhaseOperations {
		t.Errorf("lifecycle = %v, want generator value preserved", md.Lifecycles)
	}
	if (*md.Component.Licenses)[0].License.Name != "generator-license" {
		t.Errorf("primary license = %+v, want generator value preserved", md.Component.Licenses)
	}
	if refs := *md.Component.ExternalReferences; refs[0].URL != "https://generator.example/repo" {
		t.Errorf("vcs = %q, want generator value preserved", refs[0].URL)
	}
}

func TestAugmentVCSAutodetectBeatsGenerator(t *testing.T) {
	bom := baseBOM()
	applyAugment(bom, Config{}, vcsInfo{URL: "https://github.com/o/r", Commit: "deadbeef", Ref: "v1.0.0"})

	refs := *bom.Metadata.Component.ExternalReferences
	if len(refs) != 1 || refs[0].URL != "https://github.com/o/r" {
		t.Fatalf("vcs refs = %+v, want single autodetected URL (upsert, not append)", refs)
	}
	props := map[string]string{}
	for _, p := range *bom.Metadata.Component.Properties {
		props[p.Name] = p.Value
	}
	if props["cdx:vcs:commit"] != "deadbeef" || props["cdx:vcs:ref"] != "v1.0.0" {
		t.Errorf("vcs commit/ref props = %v, want deadbeef/v1.0.0", props)
	}
}

func TestAugmentSetsOptionalFields(t *testing.T) {
	bom := baseBOM()
	applyAugment(bom, Config{
		SupplierURL:     "https://acme.example",
		SupplierContact: "sec@acme.example",
		Authors:         []string{"Ada", "Grace"},
		Manufacturer:    "ACME",
		License:         "Apache-2.0",
		Lifecycle:       "build",
	}, vcsInfo{})

	md := bom.Metadata
	if md.Supplier.URL == nil || (*md.Supplier.URL)[0] != "https://acme.example" {
		t.Errorf("supplier url not set: %+v", md.Supplier.URL)
	}
	if md.Supplier.Contact == nil || (*md.Supplier.Contact)[0].Email != "sec@acme.example" {
		t.Errorf("supplier contact email not set: %+v", md.Supplier.Contact)
	}
	if md.Authors == nil || len(*md.Authors) != 2 || (*md.Authors)[0].Name != "Ada" {
		t.Errorf("authors not set: %+v", md.Authors)
	}
	if md.Manufacturer == nil || md.Manufacturer.Name != "ACME" {
		t.Errorf("manufacturer not set: %+v", md.Manufacturer)
	}
	if md.Lifecycles == nil || (*md.Lifecycles)[0].Phase != cdx.LifecyclePhaseBuild {
		t.Errorf("lifecycle not set: %+v", md.Lifecycles)
	}
	if md.Component.Licenses == nil || (*md.Component.Licenses)[0].License.ID != "Apache-2.0" {
		t.Errorf("primary-component license = %+v, want id Apache-2.0 (flag beats generator)", md.Component.Licenses)
	}
}

func TestLicenseFrom(t *testing.T) {
	if lc := licenseFrom("Apache-2.0"); lc.License == nil || lc.License.ID != "Apache-2.0" || lc.Expression != "" {
		t.Errorf("single id → license.id, got %+v", lc)
	}
	if lc := licenseFrom("MIT OR Apache-2.0"); lc.Expression != "MIT OR Apache-2.0" || lc.License != nil {
		t.Errorf("expression → expression slot, got %+v", lc)
	}
}

// augment round-trips through 1.6 JSON: the wrapper decodes, applies, re-encodes.
func TestAugmentRoundTripEncodes16(t *testing.T) {
	in := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,` +
		`"metadata":{"component":{"type":"application","name":"app","bom-ref":"root"}}}`)
	out, err := augment(in, Config{SupplierName: "ACME"}, vcsInfo{})
	if err != nil {
		t.Fatalf("augment: %v", err)
	}
	if !bytes.Contains(out, []byte(`"1.6"`)) {
		t.Errorf("output not 1.6:\n%s", out)
	}
	if !bytes.Contains(out, []byte("ACME")) {
		t.Errorf("supplier not in output:\n%s", out)
	}
}

func TestWarnMissingConfig(t *testing.T) {
	var buf bytes.Buffer
	WarnMissingConfig(&buf, Config{SupplierName: "ACME"}) // only required field set
	out := buf.String()
	for _, flag := range []string{"--supplier-url", "--author", "--manufacturer", "--license", "--lifecycle"} {
		if !strings.Contains(out, flag) {
			t.Errorf("missing warning for %s in:\n%s", flag, out)
		}
	}

	buf.Reset()
	WarnMissingConfig(&buf, Config{
		SupplierName: "ACME", SupplierURL: "u", SupplierContact: "c",
		Authors: []string{"a"}, Manufacturer: "m", License: "l", Lifecycle: "build",
	})
	if buf.Len() != 0 {
		t.Errorf("want no warnings when all set, got:\n%s", buf.String())
	}
}
