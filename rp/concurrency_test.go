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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// TestConcurrentRPUse: one shared RP serving simultaneous login and callback
// requests must be race-free (RC review F3). Run with -race.
// propagateBindingCookie replays the state-binding cookie set during login,
// as a real browser would.
func propagateBindingCookie(rec *httptest.ResponseRecorder, req *http.Request) {
	for _, raw := range rec.Header().Values("Set-Cookie") {
		parts := strings.SplitN(raw, ";", 2)
		if len(parts) == 0 {
			continue
		}
		nameValue := strings.SplitN(parts[0], "=", 2)
		if len(nameValue) != 2 {
			continue
		}
		req.AddCookie(&http.Cookie{Name: nameValue[0], Value: nameValue[1]})
	}
}

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
				propagateBindingCookie(rec, cbReq)
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

// TestConcurrentPARAndCallback keeps PAR auth-method selection coherent while
// callbacks renegotiate the shared RP's token endpoint authentication method.
func TestConcurrentPARAndCallback(t *testing.T) {
	const secret = "secret-32-bytes-minimum-0123456789ab"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/par":
			if err := req.ParseForm(); err != nil {
				t.Errorf("ParseForm(PAR) failed: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if req.Form.Get("client_assertion") == "" {
				t.Error("PAR request missing client_assertion")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"request_uri":"urn:test:concurrent-par","expires_in":90}`)
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"access","token_type":"Bearer","expires_in":3600}`)
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()

	provider := providerWithAuthorizationAndPAR(ts.URL+"/par", "client_secret_jwt")
	provider.TokenEndpoint = ts.URL + "/token"
	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret(secret),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithScopes("accounts"),
		WithAuthMethod(AuthMethodClientSecretJWT),
		WithRequirePAR(true),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	const workers = 8
	const iterations = 20
	errs := make(chan error, workers*2)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if _, err := r.AuthorizationURL(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)); err != nil {
					errs <- fmt.Errorf("AuthorizationURL: %w", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				state := fmt.Sprintf("callback-%d-%d", worker, i)
				if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, state, CallbackCorrelation{
					CodeVerifier: "verifier",
					CreatedAt:    time.Now().UTC(),
				}); err != nil {
					errs <- fmt.Errorf("SaveCorrelation: %w", err)
					return
				}
				result, err := r.HandleCallback(callbackRequest("code", state))
				if err != nil {
					errs <- fmt.Errorf("HandleCallback: %w", err)
					return
				}
				if result.Token == nil {
					errs <- fmt.Errorf("HandleCallback returned nil Token")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
