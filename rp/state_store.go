package rp

import rpstore "github.com/Kunde21/lanyard/rp/store"

// CallbackCorrelation contains callback correlation values owned by the RP package.
//
// These fields are written by RP during authorization start and consumed during callback.
// Callers should treat them as RP-managed internals.
type CallbackCorrelation = rpstore.CallbackCorrelation

// StateScope groups RP-managed callback correlation data with caller-owned values.
//
// Values are opaque named blobs controlled by callers; RP stores and retrieves them but
// does not interpret their contents.
type StateScope = rpstore.StateScope

// CorrelationStore persists RP-managed callback correlation data.
//
// Core RP authorization and callback handling require only this narrow contract.
type CorrelationStore = rpstore.CorrelationStore

// StateScopeStore persists and loads complete state scopes.
type StateScopeStore = rpstore.StateScopeStore

// ValueStore persists caller-owned values scoped by state.
type ValueStore = rpstore.ValueStore

// StateStore persists callback correlation data and caller-owned values scoped by state.
//
// Supported implementations are provided by `rp/store/memory` and `rp/store/cookie`.
type StateStore = rpstore.StateStore
