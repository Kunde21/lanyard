package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

func handleConformanceJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	alias := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/conformance/jwks/"))
	if alias == "" {
		http.NotFound(w, r)
		return
	}
	if decodedAlias, err := url.PathUnescape(alias); err == nil {
		alias = strings.TrimSpace(decodedAlias)
	}
	runtimeCfg, ok := conformanceRuntimes.Lookup(alias)
	if !ok {
		http.NotFound(w, r)
		return
	}

	jwks, err := conformancePublicJWKS(runtimeCfg.ClientAuthType)
	if err != nil {
		http.Error(w, "failed to load jwks", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}
