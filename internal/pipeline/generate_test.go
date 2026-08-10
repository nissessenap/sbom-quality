package pipeline

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// -main is passed only when a main path is set, and the module path stays last
// (cyclonedx-gomod takes it positionally). Empty means gomod's own default of
// "." — passing an empty -main value instead would be an error (#80).
func TestGomodArgs(t *testing.T) {
	base := []string{"app", "-json", "-licenses", "-output-version", "1.6"}

	if got, want := gomodArgs("/work", ""), append(slices.Clone(base), "/work"); !slices.Equal(got, want) {
		t.Errorf("no main path: got %v, want %v", got, want)
	}
	if got, want := gomodArgs("/work", "./cmd/app"), append(slices.Clone(base), "-main", "./cmd/app", "/work"); !slices.Equal(got, want) {
		t.Errorf("with main path: got %v, want %v", got, want)
	}
}

// A tool that outlives toolTimeout aborts with a tool-named timeout error (not a
// generic exec failure). Uses `sleep` so no project binary is required.
func TestRunToolTimeout(t *testing.T) {
	orig := toolTimeout
	toolTimeout = 10 * time.Millisecond
	defer func() { toolTimeout = orig }()

	_, err := runTool("sleep", "10")
	if err == nil || !strings.Contains(err.Error(), "sleep timed out after") {
		t.Fatalf("want 'sleep timed out after' error, got %v", err)
	}
}
