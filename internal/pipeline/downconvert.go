package pipeline

import (
	"bytes"
	"fmt"

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
	var out bytes.Buffer
	enc := cdx.NewBOMEncoder(&out, cdx.BOMFileFormatJSON).SetPretty(true)
	if err := enc.EncodeVersion(&bom, cdx.SpecVersion1_6); err != nil {
		return nil, fmt.Errorf("encode SBOM at 1.6: %w", err)
	}
	return out.Bytes(), nil
}

// downConvertTo16 re-encodes a modern-trivy 1.7 document at 1.6, unchanged.
func downConvertTo16(in []byte) ([]byte, error) {
	return reencode16(in, nil)
}
