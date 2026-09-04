package conformanceharness

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestComposeArgs_ForceRecreateAllServices(t *testing.T) {
	got, err := composeArgs("up", "-d", "--force-recreate")
	if err != nil {
		t.Fatalf("composeArgs() failed: %v", err)
	}
	composeFile, err := repoPath("conformance/docker-compose.yml")
	if err != nil {
		t.Fatalf("repoPath() failed: %v", err)
	}
	want := []string{"compose", "-f", composeFile, "up", "-d", "--force-recreate"}
	if _, statErr := os.Stat(composeFile[:strings.LastIndex(composeFile, "/")] + "/docker-compose.override.yml"); statErr == nil {
		want = []string{"compose", "-f", composeFile, "-f", composeFile[:strings.LastIndex(composeFile, "/")] + "/docker-compose.override.yml", "up", "-d", "--force-recreate"}
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("composeArgs() mismatch (-want +got):\n%s", diff)
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
