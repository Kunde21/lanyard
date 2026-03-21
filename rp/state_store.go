package rp

import "time"

// StateData contains callback correlation values saved at authorization start.
type StateData struct {
	Nonce                  string
	CodeVerifier           string
	CreatedAt              time.Time
	Expiry                 time.Time
	Issuer                 string
	RequestURI             string
	UsedPAR                bool
	UserInfoTokenTransport UserInfoTokenTransport
}

// StateStore stores and consumes state correlation data.
type StateStore interface {
	Save(state string, data StateData)
	Load(state string) (StateData, bool)
	Delete(state string)
}
