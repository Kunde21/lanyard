package rp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Token represents a token endpoint response shared by the browser and client
// credentials entrypoints.
type Token struct {
	// AccessToken is the OAuth 2.0 bearer token for API calls.
	AccessToken string `json:"access_token"`
	// TokenType is usually "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the token lifetime reported by the token endpoint, in seconds.
	ExpiresIn int64 `json:"expires_in"`
	// IDToken is set for authorization code responses that include an ID token.
	IDToken string `json:"id_token,omitempty"`
	// RefreshToken is set when the provider issues a refresh token.
	RefreshToken string `json:"refresh_token,omitempty"`
	// GrantID identifies the underlying grant the tokens were issued under
	// (grant management, draft-ietf-oauth-grant-management section 5.4). Empty
	// when the provider does not support grant management.
	GrantID string `json:"grant_id,omitempty"`
	// Scope is the granted scope string returned by the token endpoint.
	Scope string `json:"scope,omitempty"`

	raw json.RawMessage
}

type tokenJSON Token

type tokenEnvelope struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    int64           `json:"expires_in"`
	IDToken      string          `json:"id_token"`
	RefreshToken string          `json:"refresh_token"`
	GrantID      string          `json:"grant_id"`
	Scope        string          `json:"scope"`
	Raw          json.RawMessage `json:"raw,omitempty"`
}

// UnmarshalJSON decodes token fields and preserves the full provider payload
// in raw. Fields present in a persisted envelope are authoritative even when
// empty or zero. Missing fields in a legacy raw-only envelope are restored
// from its raw provider payload for backward compatibility.
func (t *Token) UnmarshalJSON(data []byte) error {
	if t == nil {
		return fmt.Errorf("token is nil")
	}

	stored := tokenEnvelope{}
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}

	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	decoded := Token{
		AccessToken:  stored.AccessToken,
		TokenType:    stored.TokenType,
		ExpiresIn:    stored.ExpiresIn,
		IDToken:      stored.IDToken,
		RefreshToken: stored.RefreshToken,
		GrantID:      stored.GrantID,
		Scope:        stored.Scope,
	}
	rawPayload := json.RawMessage(data)
	if persistedRaw, ok := fields["raw"]; ok {
		rawPayload = persistedRaw
		fromRaw := tokenJSON{}
		if err := json.Unmarshal(rawPayload, &fromRaw); err != nil {
			return err
		}
		if _, present := fields["access_token"]; !present {
			decoded.AccessToken = fromRaw.AccessToken
		}
		if _, present := fields["token_type"]; !present {
			decoded.TokenType = fromRaw.TokenType
		}
		if _, present := fields["expires_in"]; !present {
			decoded.ExpiresIn = fromRaw.ExpiresIn
		}
		if _, present := fields["id_token"]; !present {
			decoded.IDToken = fromRaw.IDToken
		}
		if _, present := fields["refresh_token"]; !present {
			decoded.RefreshToken = fromRaw.RefreshToken
		}
		if _, present := fields["grant_id"]; !present {
			decoded.GrantID = fromRaw.GrantID
		}
		if _, present := fields["scope"]; !present {
			decoded.Scope = fromRaw.Scope
		}
	}

	decoded.raw = append(json.RawMessage(nil), rawPayload...)
	*t = decoded
	return nil
}

// MarshalJSON persists every token lifecycle field, including empty and zero
// values, together with the preserved raw provider payload. Explicit zero
// values therefore remain authoritative on a later unmarshal.
func (t Token) MarshalJSON() ([]byte, error) {
	rawPayload := t.raw
	if len(rawPayload) == 0 {
		payload, err := json.Marshal(tokenJSON(t))
		if err != nil {
			return nil, err
		}
		rawPayload = payload
	}
	return json.Marshal(tokenEnvelope{
		AccessToken:  t.AccessToken,
		TokenType:    t.TokenType,
		ExpiresIn:    t.ExpiresIn,
		IDToken:      t.IDToken,
		RefreshToken: t.RefreshToken,
		GrantID:      t.GrantID,
		Scope:        t.Scope,
		Raw:          rawPayload,
	})
}

// DecodeRaw unmarshals the original preserved provider token payload into
// target. Editing Token fields does not alter or securely erase credentials
// or other values retained in that raw payload.
func (t Token) DecodeRaw(target any) error {
	if target == nil {
		return fmt.Errorf("target is nil")
	}
	if len(t.raw) == 0 {
		return fmt.Errorf("token raw payload is empty")
	}
	if err := json.Unmarshal(t.raw, target); err != nil {
		return fmt.Errorf("failed to decode token raw payload: %w", err)
	}
	return nil
}

// Extra returns a string field from the preserved raw token payload.
func (t Token) Extra(name string) (string, error) {
	field := strings.TrimSpace(name)
	if field == "" {
		return "", fmt.Errorf("field name is required")
	}
	if len(t.raw) == 0 {
		return "", fmt.Errorf("token raw payload is empty")
	}
	values := map[string]json.RawMessage{}
	if err := json.Unmarshal(t.raw, &values); err != nil {
		return "", fmt.Errorf("failed to decode token raw payload: %w", err)
	}
	rawValue, ok := values[field]
	if !ok {
		return "", fmt.Errorf("token raw payload field %q not found", field)
	}
	var value string
	if err := json.Unmarshal(rawValue, &value); err != nil {
		return "", fmt.Errorf("token raw payload field %q is not a string: %w", field, err)
	}
	return value, nil
}

func parseTokenResponse(data []byte, token *Token) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}
	type alias tokenJSON
	decoded := alias{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*token = Token(decoded)
	token.raw = append(token.raw[:0], data...)
	return nil
}

// TokenSource provides OAuth 2.0 access tokens.
type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
}

// Scopes configuration option for client credentials flow.
type Scopes []string

type tokenScopesKey struct{}

// WithTokenScopes returns a context with per-request scopes for client credentials token requests.
// These scopes override the default scopes configured when creating the ClientCredentials.
func WithTokenScopes(ctx context.Context, scopes ...string) context.Context {
	if ctx == nil {
		return nil
	}
	clonedScopes := make([]string, len(scopes))
	copy(clonedScopes, scopes)
	return context.WithValue(ctx, tokenScopesKey{}, clonedScopes)
}

func tokenScopesFromContext(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	scopes, _ := ctx.Value(tokenScopesKey{}).([]string)
	return scopes
}

type tokenResourcesKey struct{}

type resourceContextValue struct {
	resources []string
	err       error
}

// WithTokenResources returns a context with per-request resource indicators for
// token requests that support request-time overrides (RFC 8707).
func WithTokenResources(ctx context.Context, resources ...string) context.Context {
	if ctx == nil {
		return nil
	}
	normalized, err := normalizeResources(resources)
	if err != nil {
		return context.WithValue(ctx, tokenResourcesKey{}, resourceContextValue{err: err})
	}
	return context.WithValue(ctx, tokenResourcesKey{}, resourceContextValue{resources: normalized})
}

func tokenResourcesFromContext(ctx context.Context) []string {
	resources, _ := tokenResourcesAndErrorFromContext(ctx)
	return resources
}

func tokenResourcesAndErrorFromContext(ctx context.Context) ([]string, error) {
	if ctx == nil {
		return nil, nil
	}
	value, _ := ctx.Value(tokenResourcesKey{}).(resourceContextValue)
	return value.resources, value.err
}
