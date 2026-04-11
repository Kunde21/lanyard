package cache_test

import (
	"fmt"

	"github.com/Kunde21/lanyard/cache"
)

func ExampleNewStore() {
	store := cache.NewStore[string]()

	store.Set("key", "value")
	v, ok := store.Get("key")

	fmt.Println(ok)
	fmt.Println(v)
	// Output:
	// true
	// value
}
