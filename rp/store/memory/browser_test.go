package memory

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
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
			profileDir := t.TempDir()
			output := runChromium(t, browser, profileDir, rpURL+"/start")
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

	initiatingProfile := t.TempDir()
	if output := runChromium(t, browser, initiatingProfile, rpURL+"/bind"); !strings.Contains(output, "binding-created") {
		t.Fatalf("initiating browser did not create binding; browser output:\n%s", output)
	}

	otherProfile := t.TempDir()
	if output := runChromium(t, browser, otherProfile, rpURL+"/callback"); !strings.Contains(output, "callback-rejected") {
		t.Fatalf("different browser was not rejected; browser output:\n%s", output)
	}

	if output := runChromium(t, browser, initiatingProfile, rpURL+"/callback"); !strings.Contains(output, "callback-accepted") {
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

func browserSiteURL(serverURL, host string) string {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		panic(err)
	}
	_, port, _ := strings.Cut(parsed.Host, ":")
	parsed.Host = host + ":" + port
	return parsed.String()
}

func runChromium(t *testing.T, browser, profileDir, target string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	args := []string{
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-background-networking",
		"--no-first-run",
		"--no-proxy-server",
		"--ignore-certificate-errors",
		"--host-resolver-rules=MAP rp.test 127.0.0.1, MAP issuer.test 127.0.0.1",
		"--user-data-dir=" + filepath.Clean(profileDir),
		"--dump-dom",
		target,
	}
	output, err := exec.CommandContext(ctx, browser, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("Chromium failed: %v\n%s", err, output)
	}
	return string(output)
}
