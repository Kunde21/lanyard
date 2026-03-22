package store

import (
	"context"
	"net/http"
	"time"
)

// CallbackCorrelation contains callback correlation values owned by the RP package.
//
// Callers should treat these fields as RP-managed data used to validate and complete
// authorization callbacks.
type CallbackCorrelation struct {
	Nonce                  string
	CodeVerifier           string
	CreatedAt              time.Time
	Expiry                 time.Time
	Issuer                 string
	RequestURI             string
	UsedPAR                bool
	UserInfoTokenTransport string
}

// StateScope groups RP-managed callback correlation data with caller-owned values.
//
// Values are opaque named blobs owned by callers. RP only persists and retrieves them.
type StateScope struct {
	Correlation CallbackCorrelation
	Values      map[string][]byte
}

// StateStore persists RP callback correlation data and caller-owned state values.
//
// Implementations may require HTTP request/response access for persistence operations.
// Mutating operations receive both request and response writer so implementations can
// persist updates (for example by writing session cookies).
type StateStore interface {
	SaveCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state string, correlation CallbackCorrelation) error
	ConsumeCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) (CallbackCorrelation, bool, error)
	LoadState(ctx context.Context, req *http.Request, state string) (StateScope, bool, error)
	DeleteState(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) error

	SaveValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string, value []byte) error
	LoadValue(ctx context.Context, req *http.Request, state, name string) ([]byte, bool, error)
	DeleteValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string) error
	ConsumeValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string) ([]byte, bool, error)
}
