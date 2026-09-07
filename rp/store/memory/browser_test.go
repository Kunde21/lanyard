package memory

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	rpstore "github.com/Kunde21/lanyard/rp/store"

	"github.com/Kunde21/lanyard/internal/browsertest"
)

func TestCorrelationBrowserBindingCrossSiteCallbacks(t *testing.T) {
	browser := browsertest.ChromiumPath(t)

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

			rpURL = browsertest.SiteURL(rpServer.URL, "rp.test")
			issuerURL = browsertest.SiteURL(issuerServer.URL, "issuer.test")
			close(ready)
			profileDir := browsertest.ProfileDir(t)
			output := browsertest.Run(t, browser, profileDir, rpURL+"/start", []string{"callback-accepted"})
			if !strings.Contains(output, "callback-accepted") {
				t.Fatalf("cross-site %s callback was not accepted; browser output:\n%s", mode, output)
			}
		})
	}
}

func TestCorrelationBrowserBindingRejectsDifferentBrowser(t *testing.T) {
	browser := browsertest.ChromiumPath(t)
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
	rpURL = browsertest.SiteURL(rpServer.URL, "rp.test")

	initiatingProfile := browsertest.ProfileDir(t)
	// Natural exit (no markers): the binding cookie must be flushed to the
	// profile for the later same-profile launch.
	if output := browsertest.Run(t, browser, initiatingProfile, rpURL+"/bind", nil); !strings.Contains(output, "binding-created") {
		t.Fatalf("initiating browser did not create binding; browser output:\n%s", output)
	}

	otherProfile := browsertest.ProfileDir(t)
	if output := browsertest.Run(t, browser, otherProfile, rpURL+"/callback", []string{"callback-rejected"}); !strings.Contains(output, "callback-rejected") {
		t.Fatalf("different browser was not rejected; browser output:\n%s", output)
	}

	if output := browsertest.Run(t, browser, initiatingProfile, rpURL+"/callback", []string{"callback-accepted"}); !strings.Contains(output, "callback-accepted") {
		t.Fatalf("initiating browser could not consume correlation; browser output:\n%s", output)
	}
}

// TestCorrelationBindingRejectsSiblingDomainCookieInjection: a sibling-site
// page cannot plant the binding cookie with a Domain attribute - the
// __Host- prefix makes the browser refuse it outright, so the RP's binding
// is always host-only (third RC review T1).
func TestCorrelationBindingRejectsSiblingDomainCookieInjection(t *testing.T) {
	browser := browsertest.ChromiumPath(t)
	store := New(time.Minute)
	const state = "injection-state"
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
			fmt.Fprint(w, "binding-created")
		default:
			http.NotFound(w, r)
		}
	}))
	defer rpServer.Close()

	issuerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-ready
		if r.URL.Path != "/attack" {
			http.NotFound(w, r)
			return
		}
		// Attacker page on the sibling site tries to plant the binding
		// cookie for the whole registrable domain, plus a plain prefixed
		// attempt. Both must be rejected by the browser because __Host-
		// forbids Domain attributes (and this page is not the RP host).
		fmt.Fprintf(w, `<!doctype html><script>
document.cookie = "__Host-lanyard_state_binding=attacker-known; Domain=issuer.test; Path=/; Secure";
document.cookie = "__Host-lanyard_state_binding=attacker-known; Domain=issuer.test; Path=/";
var readable = document.cookie.indexOf("__Host-lanyard_state_binding=") !== -1 ? "injected" : "refused";
document.title = "cookie-" + readable;
</script><p id="result">cookie-unknown</p><script>document.getElementById('result').textContent = document.title;</script>`)
	}))
	defer issuerServer.Close()

	rpURL = browsertest.SiteURL(rpServer.URL, "rp.test")
	issuerURL = browsertest.SiteURL(issuerServer.URL, "issuer.test")
	close(ready)

	profile := browsertest.ProfileDir(t)
	attack := browsertest.Run(t, browser, profile, issuerURL+"/attack", []string{"cookie-refused", "cookie-injected"})
	if !strings.Contains(attack, "cookie-refused") {
		t.Fatalf("sibling-domain cookie was injected despite __Host- prefix; browser output:\n%s", attack)
	}

	// The victim browser (same profile the attacker page ran in) starts a
	// login at the RP: no hostile binding cookie may be visible, and the
	// flow must create its own host-only binding.
	legit := browsertest.Run(t, browser, profile, rpURL+"/start", []string{"binding-created"})
	if !strings.Contains(legit, "binding-created") {
		t.Fatalf("legitimate binding not created in attacked profile; browser output:\n%s", legit)
	}
}
