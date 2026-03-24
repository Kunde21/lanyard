package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

func handleConformanceRuntime(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var cfg rpRuntimeConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid runtime payload", http.StatusBadRequest)
			return
		}
		slog.Info("registering runtime", "alias", cfg.Alias, "issuer", cfg.Issuer, "client_id", cfg.ClientID)
		if err := conformanceRuntimes.Register(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		alias := strings.TrimSpace(r.URL.Query().Get("alias"))
		if alias == "" {
			http.Error(w, "alias is required", http.StatusBadRequest)
			return
		}
		conformanceRuntimes.Delete(alias)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
