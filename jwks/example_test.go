package jwks_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/Kunde21/lanyard/jwks"
)

func ExampleNewRemoteKeySet() {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[{
			"kty":"RSA",
			"kid":"key-1",
			"use":"sig",
			"alg":"RS256",
			"n":"2ieuB-8BJ19bpi_0iqt8mi-31jPpO4NHNFeH-AeG7dIwBlhVVUGbJ2yhvHALutgeMfzn5OtbX75Szul7lmAxrGSAkYqg1SuRzJOJJ0-5rxWrismoIDBjSL4jCTL0HYFWePQzoB_RFPaLqiuye5FQV02iG2b8f-EgpCxTkN8rudtoCurIFDLxc4eu7TkLrS5prfcAj74Yub2qXlJtE0Q5syjxbiNI5gg_Tqok_Klfi7glU8cj1ahsvDqPXiMqKnQ3zZr_UTnkT3Vb_q3nyBukSZUF-gduBnAg17sCayPw1EBBFhq04VJRYDDL30b6oq8eaFfnhMD0xo6HG7gZY71caQ",
			"e":"AQAB"
		}]}`)
	}))
	defer server.Close()

	ks, err := jwks.NewRemoteKeySet(
		server.URL+"/jwks",
		jwks.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	keys, err := ks.Keys(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(len(keys) > 0)
	// Output: true
}
