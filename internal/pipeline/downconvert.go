package pipeline

import (
	"bytes"
	"fmt"
	"io"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// reencode16 decodes a CycloneDX JSON document, runs apply (nil for a pure
// down-convert), and re-encodes at spec version 1.6. EncodeVersion strips only
// the 1.7-only fields; component data is preserved. Shared by the three native
// stages (down-convert, augment, quality-patch).
func reencode16(in []byte, apply func(*cdx.BOM)) ([]byte, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(in), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("decode SBOM: %w", err)
	}
	if apply != nil {
		apply(&bom)
	}
	return encode16(&bom)
}

// encode16 serializes an in-memory BOM at spec version 1.6 (pretty JSON). Shared by
// reencode16 and acquireSBOM, so a caller already holding a decoded BOM need not
// round-trip through the bytes a second time.
func encode16(bom *cdx.BOM) ([]byte, error) {
	var out bytes.Buffer
	enc := cdx.NewBOMEncoder(&out, cdx.BOMFileFormatJSON).SetPretty(true)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, fmt.Errorf("encode SBOM at 1.6: %w", err)
	}
	return out.Bytes(), nil
}

// downConvertTo16 re-encodes a modern-trivy 1.7 document at 1.6, unchanged.
func downConvertTo16(in []byte) ([]byte, error) {
	return reencode16(in, nil)
}

// minSBOMSpec is the oldest CycloneDX version --sbom accepts. 1.5 is the floor because
// cargo-cyclonedx maxes at 1.5 (its 1.6 support is upstream #769, still open); anything
// older is genuinely lower-fidelity and rejected loudly. cyclonedx-go decodes 1.5 into
// the same version-agnostic BOM, so encode16 up-converts it to 1.6 losslessly.
const minSBOMSpec = cdx.SpecVersion1_5

// acquireSBOM reads a bring-your-own CycloneDX dependency SBOM (the --sbom source),
// validates it at the trust boundary, and normalizes it to 1.6. Decoding is the
// CycloneDX-validity check (a non-CycloneDX blob fails to decode); a document below
// minSBOMSpec is rejected loudly; 1.5 is up-converted and 1.7 down-converted, each with a
// stderr warning (warn). Normalization reuses encode16 — the only new logic is the guard.
func acquireSBOM(path string, warn io.Writer) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("decode --sbom %s: %w", path, err)
	}
	// Well-formed JSON that isn't CycloneDX (e.g. SPDX) decodes without error but has
	// no bomFormat; reject it here so the message isn't a confusing "CycloneDX 0 is below 1.5".
	if bom.BOMFormat != cdx.BOMFormat {
		return nil, fmt.Errorf("--sbom %s: not a CycloneDX document (bomFormat=%q)", path, bom.BOMFormat)
	}
	switch {
	case bom.SpecVersion < minSBOMSpec:
		return nil, fmt.Errorf("--sbom %s: CycloneDX %s is below the %s minimum", path, bom.SpecVersion, minSBOMSpec)
	case bom.SpecVersion < cdx.SpecVersion1_6:
		fmt.Fprintf(warn, "sbom-quality: warning: --sbom %s is CycloneDX %s; up-converting to 1.6\n", path, bom.SpecVersion)
	case bom.SpecVersion > cdx.SpecVersion1_6:
		fmt.Fprintf(warn, "sbom-quality: warning: --sbom %s is CycloneDX %s; down-converting to 1.6\n", path, bom.SpecVersion)
	}
	return encode16(&bom)
}
