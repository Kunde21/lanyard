package conformanceharness

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repoRoot() (string, error) {
	if envRoot := os.Getenv("LANYARD_REPO_ROOT"); envRoot != "" {
		if root, err := findRepoRoot(envRoot); err == nil {
			return root, nil
		}
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to resolve caller path")
	}
	if root, err := findRepoRoot(filepath.Dir(file)); err == nil {
		return root, nil
	}

	wd, err := os.Getwd()
	if err == nil {
		if root, findErr := findRepoRoot(wd); findErr == nil {
			return root, nil
		}
	}

	return "", fmt.Errorf("failed to locate repository root from %q", file)
}

func findRepoRoot(start string) (string, error) {
	dir := filepath.Clean(start)
	for {
		candidate := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(candidate); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("failed to locate repository root from %q", start)
		}
		dir = parent
	}
}

func repoPath(parts ...string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	all := append([]string{root}, parts...)
	return filepath.Join(all...), nil
}

const conformanceCertsSetupMsg = "Set LANYARD_REPO_ROOT or run: bash conformance/scripts/setup.sh"

func skipIfConformanceCertsMissing(t *testing.T) {
	t.Helper()
	dir, err := repoPath("conformance/certs")
	if err != nil {
		t.Skipf("conformance certs dir not found: %v. %s", err, conformanceCertsSetupMsg)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skipf("conformance certs dir missing at %q. %s", dir, conformanceCertsSetupMsg)
	}
}
