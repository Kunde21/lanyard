package conformanceharness

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRepoPath_UsesConfiguredRepoRoot(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(go.mod) failed: %v", err)
	}
	t.Setenv("LANYARD_REPO_ROOT", repoDir)
	got, err := repoPath("conformance", "README.md")
	if err != nil {
		t.Fatalf("repoPath() failed: %v", err)
	}
	want := filepath.Join(repoDir, "conformance", "README.md")
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("repoPath() mismatch (-want +got):\n%s", diff)
	}
}
