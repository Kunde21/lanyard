// Package browsertest drives a real headless Chromium for SameSite and
// cookie-binding regressions that HTTP-level tests cannot prove.
package browsertest

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ChromiumPath locates a Chromium binary or calls tb.Skip.
func ChromiumPath(tb testingTB) string {
	tb.Helper()
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome"} {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}
	tb.Skip("Chromium is not installed; real-browser SameSite coverage skipped")
	return ""
}

// SiteURL rewrites an httptest server URL to the given host, for use with
// HostResolverRules.
func SiteURL(serverURL, host string) string {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		panic(err)
	}
	_, port, _ := strings.Cut(parsed.Host, ":")
	parsed.Host = host + ":" + port
	return parsed.String()
}

// ProfileDir creates a scratch Chromium profile whose cleanup tolerates
// browser child processes still writing after the kill that follows marker
// detection.
func ProfileDir(tb testingTB) string {
	tb.Helper()
	dir, err := os.MkdirTemp("", "chromium-profile-*")
	if err != nil {
		tb.Fatalf("MkdirTemp() failed: %v", err)
	}
	tb.Cleanup(func() {
		for attempt := 0; attempt < 10; attempt++ {
			if err := os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	return dir
}

// Run launches headless Chromium with --dump-dom and returns its output as
// soon as one of the markers appears on stdout. Success is driven by page
// content, not process exit: some CI environments dump the DOM but hang at
// shutdown, which must not fail a successful navigation.
func Run(tb testingTB, browser, profileDir, target string, markers []string) string {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	args := []string{
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-background-networking",
		"--disable-crash-reporter",
		"--disable-component-update",
		"--no-first-run",
		"--no-proxy-server",
		"--ignore-certificate-errors",
		"--host-resolver-rules=MAP rp.test 127.0.0.1, MAP issuer.test 127.0.0.1",
		"--user-data-dir=" + filepath.Clean(profileDir),
		"--dump-dom",
		target,
	}
	cmd := exec.CommandContext(ctx, browser, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		tb.Fatalf("Chromium stdout pipe failed: %v", err)
	}
	if err := cmd.Start(); err != nil {
		tb.Fatalf("Chromium failed to start: %v", err)
	}

	var collected strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			collected.WriteString(line)
			collected.WriteByte('\n')
			for _, marker := range markers {
				if strings.Contains(line, marker) {
					_ = cmd.Process.Kill()
					return
				}
			}
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		tb.Fatalf("Chromium timed out after %v; browser output:\n%s", 90*time.Second, collected.String())
	}
	_ = cmd.Wait()
	return collected.String()
}

// testingTB is the subset of testing.T used by this package.
type testingTB interface {
	Helper()
	Skip(args ...any)
	Fatalf(format string, args ...any)
	Cleanup(f func())
}

var _ = fmt.Sprintf // keep fmt for future diagnostics
