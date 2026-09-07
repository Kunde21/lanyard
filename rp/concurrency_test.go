package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// TestConcurrentRPUse: one shared RP serving simultaneous login and callback
// requests must be race-free (RC review F3). Run with -race.
func TestConcurrentRPUse(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()
	issuer := ""

	var mu sync.Mutex
	nonceByCode := map[string]string{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer": %q, "authorization_endpoint": %q, "token_endpoint": %q,
				"jwks_uri": %q, "userinfo_endpoint": %q,
				"response_types_supported": ["code"], "subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"],
				"token_endpoint_auth_methods_supported": ["client_secret_basic"]}`,
				issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks", issuer+"/userinfo")
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"sub":"sub-1"}`)
		default:
			// token endpoint: issue a token carrying the nonce the RP sent
			// for this authorization transaction.
			_ = r.ParseForm()
			mu.Lock()
			nonce := nonceByCode[r.PostFormValue("code")]
			mu.Unlock()
			claims := map[string]any{
				"iss": issuer, "sub": "sub-1", "aud": []string{"client"},
				"exp": now.Add(30 * time.Minute).Unix(), "iat": now.Unix(),
				"nonce": nonce,
			}
			fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}`,
				signIDToken(t, key, "kid-1", claims))
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(context.Background(), issuer,
		WithClientID("client"),
		WithClientSecret("secret-32-bytes-minimum-0123456789ab"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	const workers = 12
	const iterations = 3
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			_ = w
			for i := 0; i < iterations; i++ {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil).WithContext(context.Background())
				authURL, err := r.AuthorizationURL(rec, req)
				if err != nil {
					errs <- fmt.Errorf("AuthorizationURL: %w", err)
					return
				}
				parsed, err := url.Parse(authURL)
				if err != nil {
					errs <- fmt.Errorf("parse auth url: %w", err)
					return
				}
				state := parsed.Query().Get("state")
				if state == "" {
					errs <- fmt.Errorf("missing state")
					return
				}

				code := fmt.Sprintf("code-%d-%d", w, i)
				nonce := parsed.Query().Get("nonce")
				mu.Lock()
				nonceByCode[code] = nonce
				mu.Unlock()

				cbRec := httptest.NewRecorder()
				cbReq := httptest.NewRequest(http.MethodGet, "https://rp.test/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil).WithContext(context.Background())
				result, err := r.HandleCallback(cbRec, cbReq)
				if err != nil {
					errs <- fmt.Errorf("HandleCallback: %w", err)
					return
				}
				if result.Subject != "sub-1" {
					errs <- fmt.Errorf("subject = %q", result.Subject)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
