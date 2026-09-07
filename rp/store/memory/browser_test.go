package memory

import (
	"bufio"
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rpstore "github.com/Kunde21/lanyard/rp/store"
)

func TestCorrelationBrowserBindingCrossSiteCallbacks(t *testing.T) {
	browser := chromiumPath(t)

	for _, mode := range []string{"query", "form_post"} {
		t.Run(mode, func(t *testing.T) {
			store := New(time.Minute)
			state := "state-" + mode
			var rpURL, issuerURL string
			ready := make(chan struct{})

			rpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-ready
				switch r.URL.Path {
				case "/start":
					if err := store.SaveCorrelation(r.Context(), w, r, state, rpstore.CallbackCorrelation{Nonce: "nonce"}); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					http.Redirect(w, r, issuerURL+"/authorize?mode="+url.QueryEscape(mode)+"&state="+url.QueryEscape(state), http.StatusFound)
				case "/callback":
					if err := r.ParseForm(); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					_, ok, err := store.ConsumeCorrelation(r.Context(), w, r, r.FormValue("state"))
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					if !ok {
						fmt.Fprint(w, "callback-rejected")
						return
					}
					fmt.Fprint(w, "callback-accepted")
				default:
					http.NotFound(w, r)
				}
			}))
			defer rpServer.Close()

			issuerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-ready
				state := r.URL.Query().Get("state")
				if mode == "query" {
					http.Redirect(w, r, rpURL+"/callback?state="+url.QueryEscape(state), http.StatusFound)
					return
				}
				fmt.Fprintf(w, `<!doctype html><form id="callback" method="post" action="%s/callback"><input name="state" value="%s"></form><script>document.getElementById('callback').submit()</script>`, html.EscapeString(rpURL), html.EscapeString(state))
			}))
			defer issuerServer.Close()

			rpURL = browserSiteURL(rpServer.URL, "rp.test")
			issuerURL = browserSiteURL(issuerServer.URL, "issuer.test")
			close(ready)
			profileDir := chromiumProfileDir(t)
			output := runChromiumAwait(t, browser, profileDir, rpURL+"/start", []string{"callback-accepted"})
			if !strings.Contains(output, "callback-accepted") {
				t.Fatalf("cross-site %s callback was not accepted; browser output:\n%s", mode, output)
			}
		})
	}
}

func TestCorrelationBrowserBindingRejectsDifferentBrowser(t *testing.T) {
	browser := chromiumPath(t)
	store := New(time.Minute)
	const state = "browser-bound-state"
	var rpURL string

	rpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bind":
			if err := store.SaveCorrelation(r.Context(), w, r, state, rpstore.CallbackCorrelation{Nonce: "nonce"}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "binding-created")
		case "/callback":
			_, ok, err := store.ConsumeCorrelation(r.Context(), w, r, state)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if !ok {
				fmt.Fprint(w, "callback-rejected")
				return
			}
			fmt.Fprint(w, "callback-accepted")
		default:
			http.NotFound(w, r)
		}
	}))
	defer rpServer.Close()
	rpURL = browserSiteURL(rpServer.URL, "rp.test")

	initiatingProfile := chromiumProfileDir(t)
	if output := runChromiumAwait(t, browser, initiatingProfile, rpURL+"/bind", []string{"binding-created"}); !strings.Contains(output, "binding-created") {
		t.Fatalf("initiating browser did not create binding; browser output:\n%s", output)
	}

	otherProfile := chromiumProfileDir(t)
	if output := runChromiumAwait(t, browser, otherProfile, rpURL+"/callback", []string{"callback-rejected"}); !strings.Contains(output, "callback-rejected") {
		t.Fatalf("different browser was not rejected; browser output:\n%s", output)
	}

	if output := runChromiumAwait(t, browser, initiatingProfile, rpURL+"/callback", []string{"callback-accepted"}); !strings.Contains(output, "callback-accepted") {
		t.Fatalf("initiating browser could not consume correlation; browser output:\n%s", output)
	}
}

func chromiumPath(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome"} {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}
	t.Skip("Chromium is not installed; real-browser SameSite coverage skipped")
	return ""
}

// chromiumProfileDir creates a scratch profile directory whose cleanup
// tolerates Chromium child processes still writing after the kill that
// follows marker detection (t.TempDir fails hard on that race).
func chromiumProfileDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "chromium-profile-*")
	if err != nil {
		t.Fatalf("MkdirTemp() failed: %v", err)
	}
	t.Cleanup(func() {
		for attempt := 0; attempt < 10; attempt++ {
			if err := os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	return dir
}

func browserSiteURL(serverURL, host string) string {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		panic(err)
	}
	_, port, _ := strings.Cut(parsed.Host, ":")
	parsed.Host = host + ":" + port
	return parsed.String()
}

// runChromiumAwait launches headless Chromium with --dump-dom and returns
// its output as soon as one of the markers appears on stdout. Success is
// driven by the page content, not by process exit: some CI environments
// (notably snap Chromium on GitHub runners) dump the DOM but then hang at
// shutdown, which must not fail an otherwise successful navigation
// (third RC review T6).
func runChromiumAwait(t *testing.T, browser, profileDir, target string, markers []string) string {
	t.Helper()

	// Generous deadline: cold-start fontconfig cache builds on 2-core CI
	// runners can make the first Chromium launch slow.
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
		t.Fatalf("Chromium stdout pipe failed: %v", err)
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("Chromium failed to start: %v", err)
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
		t.Fatalf("Chromium timed out after %v; browser output:\n%s", 90*time.Second, collected.String())
	}
	_ = cmd.Wait()
	return collected.String()
}
