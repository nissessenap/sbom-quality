package pipeline

import (
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// vcsInfo is the version-control provenance for the primary component: repo URL,
// commit sha, and ref (branch/tag). Autodetected from the CI env in Run().
type vcsInfo struct {
	URL, Commit, Ref string
}

// augment fills document-identity metadata (supplier/authors/manufacturer/license/
// lifecycle/VCS) on the in-memory BOM, never component data. Per-field precedence is
// flag > GH-autodetect(VCS) > generator value > absent, so a set flag overrides what
// the generator emitted and an unset one leaves it untouched. Decode → apply → encode
// at 1.6.
func augment(sbom []byte, cfg Config, vcs vcsInfo) ([]byte, error) {
	return reencode16(sbom, func(bom *cdx.BOM) { applyAugment(bom, cfg, vcs) })
}

// applyAugment is the pure BOM→BOM transform behind augment (unit-tested directly on
// in-memory fixtures). Each field writes only when its flag/autodetect value is set,
// so generator values survive absent input.
func applyAugment(bom *cdx.BOM, cfg Config, vcs vcsInfo) {
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	md := bom.Metadata

	// supplier — flag beats generator, field by field.
	if cfg.SupplierName != "" || cfg.SupplierURL != "" || cfg.SupplierContact != "" {
		if md.Supplier == nil {
			md.Supplier = &cdx.OrganizationalEntity{}
		}
		if cfg.SupplierName != "" {
			md.Supplier.Name = cfg.SupplierName
		}
		if cfg.SupplierURL != "" {
			md.Supplier.URL = &[]string{cfg.SupplierURL}
		}
		if cfg.SupplierContact != "" {
			md.Supplier.Contact = &[]cdx.OrganizationalContact{contactFrom(cfg.SupplierContact)}
		}
	}

	// authors
	if len(cfg.Authors) > 0 {
		authors := make([]cdx.OrganizationalContact, 0, len(cfg.Authors))
		for _, a := range cfg.Authors {
			authors = append(authors, cdx.OrganizationalContact{Name: a})
		}
		md.Authors = &authors
	}

	// manufacturer
	if cfg.Manufacturer != "" {
		md.Manufacturer = &cdx.OrganizationalEntity{Name: cfg.Manufacturer}
	}

	// lifecycle
	if cfg.Lifecycle != "" {
		md.Lifecycles = &[]cdx.Lifecycle{{Phase: cdx.LifecyclePhase(cfg.Lifecycle)}}
	}

	// document data license — metadata.licenses is the SBOM document's own
	// license (not any component's). CC0-1.0 by SPDX/CycloneDX convention.
	if cfg.DataLicense != "" {
		md.Licenses = &cdx.Licenses{licenseFrom(cfg.DataLicense)}
	}

	// primary-component license — a bare SPDX id lands in license.id (what
	// sbomqs credits), a multi-license expression in the top-level expression
	// slot. quality-patch (#21) later normalizes acknowledgement/unwraps.
	// ponytail: no-op when there's no primary component; trivy/gomod always emit one.
	if cfg.License != "" && md.Component != nil {
		md.Component.Licenses = &cdx.Licenses{licenseFrom(cfg.License)}
	}

	// VCS — autodetect beats generator; url as a vcs externalReference, commit/ref as
	// properties. Only when autodetect produced a URL (empty ⇒ keep generator's).
	if vcs.URL != "" && md.Component != nil {
		setVCSRef(md.Component, vcs.URL)
		if vcs.Commit != "" {
			setProperty(md.Component, "cdx:vcs:commit", vcs.Commit)
		}
		if vcs.Ref != "" {
			setProperty(md.Component, "cdx:vcs:ref", vcs.Ref)
		}
	}
}

// licenseFrom routes a --license value into the right CycloneDX slot: a compound
// SPDX expression (AND/OR/WITH) into the top-level expression, a single id into
// license.id. Getting the shape right is what makes sbomqs credit the license.
func licenseFrom(s string) cdx.LicenseChoice {
	if strings.ContainsAny(s, "()") ||
		strings.Contains(s, " OR ") || strings.Contains(s, " AND ") || strings.Contains(s, " WITH ") {
		return cdx.LicenseChoice{Expression: s}
	}
	return cdx.LicenseChoice{License: &cdx.License{ID: s}}
}

// contactFrom routes a supplier-contact string into email when it looks like one,
// else name — CycloneDX has no free-form contact slot.
func contactFrom(s string) cdx.OrganizationalContact {
	if strings.Contains(s, "@") {
		return cdx.OrganizationalContact{Email: s}
	}
	return cdx.OrganizationalContact{Name: s}
}

// setVCSRef upserts the single vcs-type externalReference URL on a component.
func setVCSRef(c *cdx.Component, url string) {
	if c.ExternalReferences != nil {
		for i := range *c.ExternalReferences {
			if (*c.ExternalReferences)[i].Type == cdx.ERTypeVCS {
				(*c.ExternalReferences)[i].URL = url
				return
			}
		}
	}
	var refs []cdx.ExternalReference
	if c.ExternalReferences != nil {
		refs = *c.ExternalReferences
	}
	refs = append(refs, cdx.ExternalReference{Type: cdx.ERTypeVCS, URL: url})
	c.ExternalReferences = &refs
}

// setProperty upserts a name→value property on a component.
func setProperty(c *cdx.Component, name, value string) {
	if c.Properties != nil {
		for i := range *c.Properties {
			if (*c.Properties)[i].Name == name {
				(*c.Properties)[i].Value = value
				return
			}
		}
	}
	var props []cdx.Property
	if c.Properties != nil {
		props = *c.Properties
	}
	props = append(props, cdx.Property{Name: name, Value: value})
	c.Properties = &props
}

// detectGitHubVCS reads VCS provenance from the GitHub Actions env. Returns a zero
// vcsInfo outside Actions (or when the vars are unset), so precedence falls through
// to the generator value. Called from Run() unless --no-ci-autodetect.
func detectGitHubVCS() vcsInfo {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return vcsInfo{}
	}
	var v vcsInfo
	if server, repo := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"); server != "" && repo != "" {
		v.URL = server + "/" + repo
	}
	v.Commit = os.Getenv("GITHUB_SHA")
	v.Ref = os.Getenv("GITHUB_REF_NAME")
	return v
}
