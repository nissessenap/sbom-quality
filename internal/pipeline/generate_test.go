package pipeline

import (
	"strings"
	"testing"
	"time"
)

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
