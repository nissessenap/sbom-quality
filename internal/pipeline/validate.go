package pipeline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// validate runs sbom-utility's CycloneDX 1.6 conformance check and returns the
// validated document. It repairs exactly one recoverable failure class: a
// license.id that sbom-utility's *embedded* SPDX list rejects. Modern generators
// (trivy) ship a newer SPDX list than the validator, so a legitimately-valid id
// — e.g. Artistic-dist, added in SPDX 3.27, emitted from a full-OS image's perl
// copyright — trips the validator's older enum. Such ids are demoted to the
// free-form license.name (always schema-valid, and no information is lost since
// the validator couldn't resolve the id anyway), then the doc is re-validated.
// Every other schema error — and a missing or broken sbom-utility — fails loud.
func validate(sbom []byte) ([]byte, error) {
	errs, err := validateReport(sbom)
	if err != nil {
		return nil, err
	}
	if len(errs) == 0 {
		return sbom, nil
	}
	stale := staleLicenseIDs(errs)
	if len(stale) == 0 {
		return nil, schemaErrorf(errs) // nothing we can safely repair
	}
	repaired, err := reencode16(sbom, func(b *cdx.BOM) { demoteLicenseIDs(b, stale) })
	if err != nil {
		return nil, err
	}
	if errs, err = validateReport(repaired); err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return nil, schemaErrorf(errs) // repair didn't clear it — fail loud
	}
	return repaired, nil
}

// schemaError is one entry of sbom-utility's `validate --format json` report.
type schemaError struct {
	Type  string `json:"type"`
	Field string `json:"field"`
	Value any    `json:"value"`
}

// validateReport runs sbom-utility over sbom and returns its schema errors (nil
// when valid). sbom-utility exits 0 with empty stdout when valid, and non-zero
// with a JSON error array on stdout when the document breaks schema; anything
// else (tool missing, crash, unparseable output) is a hard error.
func validateReport(sbom []byte) ([]schemaError, error) {
	if _, err := exec.LookPath("sbom-utility"); err != nil {
		return nil, fmt.Errorf("sbom-utility not found on PATH: %w", err)
	}
	path, err := writeTempSBOM(sbom)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("sbom-utility", "validate", "--input-file", path, "--format", "json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err == nil {
		return nil, nil // valid
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return nil, fmt.Errorf("sbom-utility validate failed: %w\n%s", err, stderr.String())
	}
	var errs []schemaError
	if jsonErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &errs); jsonErr != nil || len(errs) == 0 {
		return nil, fmt.Errorf("sbom-utility validate failed (exit %d):\n%s%s", exitErr.ExitCode(), stderr.String(), stdout.String())
	}
	return errs, nil
}

// staleLicenseIDs collects the license.id strings that failed the SPDX enum — the
// only error class validate repairs. Such an error has type "enum" and a field
// ending in ".license.id"; its value is the offending id string.
func staleLicenseIDs(errs []schemaError) map[string]bool {
	stale := map[string]bool{}
	for _, e := range errs {
		if e.Type != "enum" || !strings.HasSuffix(e.Field, ".license.id") {
			continue
		}
		if id, ok := e.Value.(string); ok && id != "" {
			stale[id] = true
		}
	}
	return stale
}

// demoteLicenseIDs moves every license whose id is in stale from the SPDX id field
// to the free-form name field, across the primary component and all (nested)
// components. The value is preserved verbatim; only the field changes.
func demoteLicenseIDs(bom *cdx.BOM, stale map[string]bool) {
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		demoteComponentLicenseIDs(bom.Metadata.Component, stale)
	}
	if bom.Components != nil {
		for i := range *bom.Components {
			demoteComponentLicenseIDs(&(*bom.Components)[i], stale)
		}
	}
}

func demoteComponentLicenseIDs(c *cdx.Component, stale map[string]bool) {
	if c.Licenses != nil {
		for i := range *c.Licenses {
			if lc := (*c.Licenses)[i].License; lc != nil && stale[lc.ID] {
				lc.Name, lc.ID = lc.ID, ""
			}
		}
	}
	if c.Components != nil {
		for i := range *c.Components {
			demoteComponentLicenseIDs(&(*c.Components)[i], stale)
		}
	}
}

// schemaErrorf renders schema errors into a fail-loud error, one line per finding.
func schemaErrorf(errs []schemaError) error {
	var b strings.Builder
	fmt.Fprintf(&b, "invalid SBOM: %d schema error(s):", len(errs))
	for _, e := range errs {
		fmt.Fprintf(&b, "\n  [%s] %s", e.Type, e.Field)
	}
	return errors.New(b.String())
}
