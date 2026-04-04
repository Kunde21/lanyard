package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Kunde21/lanyard/metadata"
)

func main() {
	issuer := "https://accounts.google.com"
	if len(os.Args) > 1 {
		issuer = os.Args[1]
	}

	client := metadata.NewClient()
	metadata, err := client.DiscoverProvider(context.Background(), issuer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discover provider: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("issuer: %s\n", metadata.Issuer)
	fmt.Printf("jwks_uri: %s\n", metadata.JWKSURI)
	fmt.Printf("response_types_supported: %v\n", metadata.ResponseTypesSupported)
}
