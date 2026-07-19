package pipeline

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// wrapperTypes are the component types sbomqs walks as first-party "wrapper"
// artifacts (the primary component promoted into .components[] by a hier-merge).
// Patches 3–4 back-fill our own supplier/license onto these.
var wrapperTypes = map[cdx.ComponentType]bool{
	cdx.ComponentTypeApplication: true,
	cdx.ComponentTypeContainer:   true,
	cdx.ComponentTypeLibrary:     true,
	cdx.ComponentTypeFramework:   true,
	cdx.ComponentTypePlatform:    true,
}

// qualityPatch applies the four native score-tuning patches (see applyQualityPatch)
// then re-encodes at 1.6. Ported from enrich-document.jq; correctness is verified by
// the sbomqs golden gate, not up-front rules.
func qualityPatch(sbom []byte) ([]byte, error) {
	return reencode16(sbom, applyQualityPatch)
}

// applyQualityPatch is the pure BOM→BOM transform behind qualityPatch (unit-tested
// directly). Four patches, all score-tuning only:
//  1. every license gets acknowledgement:declared; SPDX expressions are unwrapped to
//     license.name (CDX 1.6 rejects non-enum ids inside expressions, name is free-form).
//  2. compositions declared complete.
//  3. our own supplier (metadata.supplier) back-filled onto wrapper components lacking one.
//  4. the primary-component license back-filled onto wrapper components lacking one.
//
// Patches 3–4 assert only *our own* provenance (the doc supplier / primary license), never
// third-party suppliers we can't verify.
func applyQualityPatch(bom *cdx.BOM) {
	// 1. license normalization — walk the primary component and every component.
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		normalizeComponentLicenses(bom.Metadata.Component)
	}
	if bom.Components != nil {
		for i := range *bom.Components {
			normalizeComponentLicenses(&(*bom.Components)[i])
		}
	}

	// 2. compositions declared complete (overwrites, per the jq). A scoped entry
	// mirrors the dependency graph when present — sbomqs credits the explicit
	// completeness declaration.
	comps := []cdx.Composition{{Aggregate: cdx.CompositionAggregateComplete}}
	if bom.Dependencies != nil && len(*bom.Dependencies) > 0 {
		refs := make([]cdx.BOMReference, 0, len(*bom.Dependencies))
		for _, d := range *bom.Dependencies {
			refs = append(refs, cdx.BOMReference(d.Ref))
		}
		comps = append(comps, cdx.Composition{Aggregate: cdx.CompositionAggregateComplete, Dependencies: &refs})
	}
	bom.Compositions = &comps

	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return // no wrapper/primary to back-fill onto
	}
	md := bom.Metadata

	// doc supplier / primary license are the only faithful sources for the back-fills.
	// Each recipient gets its own copy with bom-refs cleared: sharing one supplier/
	// license object across N components would duplicate any bom-ref it carries and
	// fail sbom-utility validate (CDX 1.6 requires bom-ref uniqueness) — the guard
	// enrich-document.jq did with strip_bom_refs.
	docSupplier := md.Supplier
	docLicenses := md.Component.Licenses

	// 3. primary-component supplier back-fill (absent only).
	if md.Component.Supplier == nil {
		md.Component.Supplier = supplierCopy(docSupplier)
	}

	// 3+4. wrapper components in .components[]: back-fill supplier and license when absent.
	if bom.Components != nil {
		for i := range *bom.Components {
			c := &(*bom.Components)[i]
			if !wrapperTypes[c.Type] {
				continue
			}
			if c.Supplier == nil {
				c.Supplier = supplierCopy(docSupplier)
			}
			if (c.Licenses == nil || len(*c.Licenses) == 0) && docLicenses != nil && len(*docLicenses) > 0 {
				c.Licenses = licensesCopy(docLicenses)
			}
		}
	}
}

// supplierCopy returns a bom-ref-free shallow copy of e (nil-safe), so back-filling it
// onto a component can't duplicate a bom-ref the source carried.
func supplierCopy(e *cdx.OrganizationalEntity) *cdx.OrganizationalEntity {
	if e == nil {
		return nil
	}
	c := *e
	c.BOMRef = ""
	return &c
}

// licensesCopy returns a bom-ref-free deep copy of the license list, for the same
// bom-ref-uniqueness reason as supplierCopy.
func licensesCopy(l *cdx.Licenses) *cdx.Licenses {
	out := make(cdx.Licenses, len(*l))
	for i, lc := range *l {
		lc.BOMRef = ""
		if lc.License != nil {
			lic := *lc.License
			lic.BOMRef = ""
			lc.License = &lic
		}
		out[i] = lc
	}
	return &out
}

// normalizeComponentLicenses applies patch 1 to a component and its nested components:
// unwrap expressions to license.name and stamp acknowledgement:declared on every entry.
func normalizeComponentLicenses(c *cdx.Component) {
	if c.Licenses != nil {
		normalizeLicenses(c.Licenses)
	}
	if c.Components != nil {
		for i := range *c.Components {
			normalizeComponentLicenses(&(*c.Components)[i])
		}
	}
}

// normalizeLicenses rewrites each license choice in place: an expression is unwrapped
// (outer parens stripped) into a declared license.name; an existing license gets
// acknowledgement:declared unless it already carries one.
func normalizeLicenses(lics *cdx.Licenses) {
	for i, lc := range *lics {
		switch {
		case lc.Expression != "":
			(*lics)[i] = cdx.LicenseChoice{License: &cdx.License{
				Name:            unwrapExpression(lc.Expression),
				Acknowledgement: cdx.LicenseAcknowledgementDeclared,
			}}
		case lc.License != nil:
			if lc.License.Acknowledgement == "" {
				lc.License.Acknowledgement = cdx.LicenseAcknowledgementDeclared
			}
		}
	}
}

// unwrapExpression strips one layer of wrapping parens, matching what cyclonedx-gomod
// emits (`(MIT)`); a bare or compound expression is returned as-is.
func unwrapExpression(e string) string {
	return strings.TrimSuffix(strings.TrimPrefix(e, "("), ")")
}
