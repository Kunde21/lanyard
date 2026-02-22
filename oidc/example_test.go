package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/Kunde21/lanyard/oidc"
)

func ExampleClient_DiscoverProvider() {
	issuer := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
  "issuer": %q,
  "authorization_endpoint": %q,
  "jwks_uri": %q,
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}`,
			issuer,
			issuer+"/authorize",
			issuer+"/jwks",
		)
	}))
	defer server.Close()
	issuer = server.URL

	client := oidc.NewClient(oidc.WithHTTPClient(server.Client()))
	metadata, err := client.DiscoverProvider(context.Background(), issuer)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(metadata.Issuer)
}
