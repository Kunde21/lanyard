package conformanceharness

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultSuiteImage = "lanyard-conformance-suite:release-v5.1.39"

func ensureProvisioned(ctx context.Context, cfg harnessConfig) error {
	buildScript, err := repoPath("conformance/scripts/build_suite.sh")
	if err != nil {
		return err
	}

	if cfg.RebuildSuite || !suiteImageExists(ctx, defaultSuiteImage) {
		if err := runCommand(ctx, "bash", buildScript); err != nil {
			return fmt.Errorf("failed to build suite image: %w", err)
		}
	}

	if err := buildExampleRPBinary(ctx); err != nil {
		return fmt.Errorf("failed to build example rp binary: %w", err)
	}

	if err := composeUp(ctx); err != nil {
		return err
	}

	readyCtx, cancel := context.WithTimeout(ctx, cfg.ProvisionTimeout)
	defer cancel()
	if err := waitForSuiteReadiness(readyCtx, cfg.SuiteURL); err != nil {
		return fmt.Errorf("suite readiness probe failed: %w", err)
	}

	return nil
}

func buildExampleRPBinary(ctx context.Context) error {
	binaryPath, err := repoPath("example-rp")
	if err != nil {
		return err
	}
	return runCommand(ctx, "go", "build", "-o", binaryPath, "./cmd/example-rp")
}

func composeUp(ctx context.Context) error {
	args, err := composeArgs("up", "-d", "--force-recreate")
	if err != nil {
		return err
	}
	if err := runCommand(ctx, "docker", args...); err != nil {
		return fmt.Errorf("docker compose up failed: %w", err)
	}
	return nil
}

// composeArgs assembles a docker compose command line from the base compose
// file plus, when present, docker-compose.override.yml next to it (used for
// machine-specific adjustments such as loopback-only port bindings).
func composeArgs(command string, extra ...string) ([]string, error) {
	composeFile, err := repoPath("conformance/docker-compose.yml")
	if err != nil {
		return nil, err
	}
	args := []string{"compose", "-f", composeFile}
	if override, err := repoPath("conformance/docker-compose.override.yml"); err == nil {
		if _, statErr := os.Stat(override); statErr == nil {
			args = append(args, "-f", override)
		}
	}
	return append(args, append([]string{command}, extra...)...), nil
}

func composeDown(ctx context.Context) error {
	args, err := composeArgs("down", "-v")
	if err != nil {
		return err
	}
	if err := runCommand(ctx, "docker", args...); err != nil {
		return fmt.Errorf("docker compose down failed: %w", err)
	}
	return nil
}

func suiteImageExists(ctx context.Context, image string) bool {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", image)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func waitForSuiteReadiness(ctx context.Context, suiteURL string) error {
	probeURL := strings.TrimRight(suiteURL, "/") + "/api/plan/available"
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}},
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err == nil {
			resp, reqErr := client.Do(req)
			if reqErr == nil {
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 500 {
					return nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	root, err := repoRoot()
	if err == nil {
		cmd.Dir = root
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w; output: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
