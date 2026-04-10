package main

import (
	"net/http"
	"strings"
)

func handleRequestObject(store *requestObjectStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/request/"), "/")
		if id == "" {
			http.Error(w, "request object id required", http.StatusBadRequest)
			return
		}

		jwt, ok := store.Load(id)
		if !ok {
			http.Error(w, "request object not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jwt))
	}
}
