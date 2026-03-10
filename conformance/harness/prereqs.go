package conformanceharness

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

func validatePrerequisites(cfg harnessConfig) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("conformance harness only supports linux; got %s", runtime.GOOS)
	}

	for _, host := range []string{"suite.localhost", "rp.localhost"} {
		if err := ensureLocalHostResolution(host); err != nil {
			return err
		}
	}

	certRelPaths := []string{
		"conformance/certs/suite.localhost.pem",
		"conformance/certs/suite.localhost-key.pem",
		"conformance/certs/rp.localhost.pem",
		"conformance/certs/rp.localhost-key.pem",
		"conformance/certs/mkcert-rootCA.pem",
	}
	for _, certRelPath := range certRelPaths {
		certPath, err := repoPath(certRelPath)
		if err != nil {
			return err
		}
		if _, err := os.Stat(certPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("missing prerequisite %q; run bash conformance/scripts/setup.sh", certRelPath)
			}
			return fmt.Errorf("failed to stat prerequisite %q: %w", certRelPath, err)
		}
	}

	buildScript, err := repoPath("conformance/scripts/build_suite.sh")
	if err != nil {
		return err
	}
	if _, err := os.Stat(buildScript); err != nil {
		return fmt.Errorf("missing suite build script %q: %w", buildScript, err)
	}

	composeFile, err := repoPath("conformance/docker-compose.yml")
	if err != nil {
		return err
	}
	if _, err := os.Stat(composeFile); err != nil {
		return fmt.Errorf("missing compose file %q: %w", composeFile, err)
	}

	_ = cfg
	return nil
}

func ensureLocalHostResolution(host string) error {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("failed to resolve %q; add hosts entries from conformance/scripts/setup.sh: %w", host, err)
	}
	for _, addr := range addrs {
		if isLocalAddress(addr) {
			return nil
		}
	}
	return fmt.Errorf("%q resolves to %v, expected 127.0.0.1 or ::1", host, addrs)
}

func isLocalAddress(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
