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
		slog.Info(
			"registering runtime",
			"alias", cfg.Alias,
			"issuer", cfg.Issuer,
			"client_id", cfg.ClientID,
			"client_auth_type", cfg.ClientAuthType,
			"sender_constrain", cfg.SenderConstrain,
			"startup_action", cfg.StartupAction,
		)
		var startup runtimeStartupResponse
		if strings.TrimSpace(cfg.StartupAction) != "" {
			ctx := r.Context()
			resolved, err := resolveRPRequestFromRuntimeConfig(cfg)
			if err != nil {
				slog.Error("startup action resolution failed", "startup_action", cfg.StartupAction, "alias", cfg.Alias, "err", err)
				if cfg.StartupAllowError {
					slog.Info("startup action resolution error allowed", "startup_action", cfg.StartupAction, "alias", cfg.Alias)
				} else {
					http.Error(w, "startup action resolution failed", http.StatusInternalServerError)
					return
				}
			} else {
				startup, err = executeStartupAction(ctx, cfg, resolved)
				if err != nil {
					slog.Error("startup action failed", "startup_action", cfg.StartupAction, "alias", cfg.Alias, "err", err)
					if !cfg.StartupAllowError {
						http.Error(w, "startup action failed", http.StatusInternalServerError)
						return
					}
					slog.Info("startup action error allowed", "startup_action", cfg.StartupAction, "alias", cfg.Alias)
				}
			}
		}

		if err := conformanceRuntimes.Register(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(startup); err != nil {
			return
		}
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
