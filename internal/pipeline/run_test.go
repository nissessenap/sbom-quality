package pipeline

import (
	"strings"
	"testing"
)

// Source validation runs before any external tool, so these need no binaries.
func TestRunSourceValidation(t *testing.T) {
	t.Run("neither source", func(t *testing.T) {
		_, err := Run(Config{SupplierName: "X"})
		if err == nil || !strings.Contains(err.Error(), "at least one") {
			t.Fatalf("want 'at least one' error, got %v", err)
		}
	})

	t.Run("both sources", func(t *testing.T) {
		_, err := Run(Config{Image: "repo:tag", GoMod: "./", SupplierName: "X"})
		if err == nil || !strings.Contains(err.Error(), "not yet implemented") {
			t.Fatalf("want 'not yet implemented' error, got %v", err)
		}
	})
}
