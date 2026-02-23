package conformanceharness

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to resolve caller path")
	}

	dir := filepath.Dir(file)
	for {
		candidate := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(candidate); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("failed to locate repository root from %q", file)
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
