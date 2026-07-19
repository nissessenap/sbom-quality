package pipeline

import (
	"bytes"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// downConvertTo16 decodes a CycloneDX JSON document (modern trivy emits 1.7) and
// re-encodes it at spec version 1.6. cyclonedx-go's EncodeVersion strips only the
// 1.7-only fields; component data is preserved.
func downConvertTo16(in []byte) ([]byte, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(in), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("decode SBOM: %w", err)
	}

	var out bytes.Buffer
	enc := cdx.NewBOMEncoder(&out, cdx.BOMFileFormatJSON).SetPretty(true)
	if err := enc.EncodeVersion(&bom, cdx.SpecVersion1_6); err != nil {
		return nil, fmt.Errorf("encode SBOM at 1.6: %w", err)
	}
	return out.Bytes(), nil
}
