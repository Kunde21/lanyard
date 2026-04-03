package conformanceharness

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestComposeUpArgs_ForceRecreateAllServices(t *testing.T) {
	composeFile := "/tmp/docker-compose.yml"
	got := composeUpArgs(composeFile)
	want := []string{"compose", "-f", composeFile, "up", "-d", "--force-recreate"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("composeUpArgs() mismatch (-want +got):\n%s", diff)
	}
}

func TestConformanceComposeFile_UsesWorkspaceBinary(t *testing.T) {
	composeFile, err := repoPath("conformance/docker-compose.yml")
	if err != nil {
		t.Fatalf("repoPath() failed: %v", err)
	}

	content, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	if !strings.Contains(string(content), `command: ["/workspace/example-rp"]`) {
		t.Fatalf("compose file does not run workspace example-rp binary")
	}
}
