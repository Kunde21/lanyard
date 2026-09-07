package cookie

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	rpstore "github.com/Kunde21/lanyard/rp/store"

	"github.com/Kunde21/lanyard/internal/browsertest"
)

// TestCookieStoreCrossSiteFormPostSameSitePolicy: with the secure default
// (SameSite=Lax) a cross-site form_post callback does not carry the state
// cookie and is rejected; WithSameSite(None) restores the form_post flow
// (third RC review T5). Real browser, real SameSite enforcement.
func TestCookieStoreCrossSiteFormPostSameSitePolicy(t *testing.T) {
	browser := browsertest.ChromiumPath(t)
	const state = "formpost-state"

	newStore := func() *Store {
		store, err := New(
			[]byte("01234567890123456789012345678901"),
			[]byte("abcdef0123456789abcdef0123456789"),
		)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		return store
	}

	run := func(t *testing.T, store *Store) string {
		t.Helper()
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
				http.Redirect(w, r, issuerURL+"/authorize?state="+url.QueryEscape(state), http.StatusFound)
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
				if ok {
					fmt.Fprint(w, "callback-accepted")
				} else {
					fmt.Fprint(w, "callback-rejected")
				}
			default:
				http.NotFound(w, r)
			}
		}))
		defer rpServer.Close()

		issuerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-ready
			stateValue := r.URL.Query().Get("state")
			fmt.Fprintf(w, `<!doctype html><form id="callback" method="post" action="%s/callback"><input name="state" value="%s"></form><script>document.getElementById('callback').submit()</script>`,
				html.EscapeString(rpURL), html.EscapeString(stateValue))
		}))
		defer issuerServer.Close()

		rpURL = browsertest.SiteURL(rpServer.URL, "rp.test")
		issuerURL = browsertest.SiteURL(issuerServer.URL, "issuer.test")
		close(ready)

		return browsertest.Run(t, browser, browsertest.ProfileDir(t), rpURL+"/start",
			[]string{"callback-accepted", "callback-rejected"})
	}

	t.Run("lax default drops cookie", func(t *testing.T) {
		output := run(t, newStore())
		if !strings.Contains(output, "callback-rejected") {
			t.Fatalf("cross-site form_post unexpectedly accepted with Lax default; output:\n%s", output)
		}
	})

	t.Run("none mode carries cookie", func(t *testing.T) {
		store := newStore()
		store.cookieOptions.SameSite = http.SameSiteNoneMode
		output := run(t, store)
		if !strings.Contains(output, "callback-accepted") {
			t.Fatalf("cross-site form_post rejected with SameSite=None; output:\n%s", output)
		}
	})
}
