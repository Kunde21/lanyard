package rp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// CallbackResult contains the validated identity data returned from
// [RP.HandleCallback].
type CallbackResult struct {
	// Subject is the OpenID Connect subject from the validated ID token.
	Subject string
	// AccessToken is the OAuth 2.0 access token returned by the token endpoint.
	AccessToken string
	// UserInfo contains claims returned from the provider's UserInfo endpoint.
	UserInfo map[string]any
	// Cnf is the RFC 7800 confirmation claim parsed from the ID token, if
	// present. It binds the ID token to a proof-of-possession key (e.g. a
	// DPoP JWK thumbprint). Callers can verify the binding via
	// Confirmation.VerifyDPoPBinding / VerifyMTLSBinding. Nil when the ID
	// token carries no cnf claim.
	Cnf *Confirmation
	// GrantID identifies the underlying grant when the provider supports
	// grant management (draft-ietf-oauth-grant-management section 5.4). Use
	// it with SetGrantManagementAction / SetGrantID to merge, replace, or
	// obtain new tokens for the same grant, and with QueryGrant / RevokeGrant.
	GrantID string
	// VerifiedClaims holds the identity assurance data parsed from the ID
	// Token's verified_claims member (OpenID Connect for Identity Assurance
	// 1.0), when present. UserInfo-delivered verified claims are available
	// via ParseVerifiedClaims on the UserInfo payload. Nil when absent.
	VerifiedClaims []VerifiedClaims
}

func (r *RP) parseAuthorizationResponse(ctx context.Context, params callbackParams) (code, state, iss string, err error) {
	if r.isJARMResponse(params) {
		jarmClaims, err := r.parseJARMResponse(ctx, params.Response)
		if err != nil {
			return "", "", "", err
		}
		if jarmClaims.Error != "" {
			return "", "", "", authorizationError(jarmClaims.Error, jarmClaims.ErrorDescription)
		}
		return jarmClaims.Code, jarmClaims.State, jarmClaims.Iss, nil
	}
	if params.Error != "" {
		return "", "", "", authorizationError(params.Error, params.ErrorDescription)
	}
	return params.Code, params.State, params.Iss, nil
}

// authorizationError maps an authorization error response (RFC 6749 section
// 4.1.2.1) to an error, with a dedicated sentinel for the grant management
// invalid_grant_id code.
func authorizationError(code, description string) error {
	if code == "invalid_grant_id" {
		if description != "" {
			return fmt.Errorf("%w: %w: %s", ErrAuthorizationFailed, ErrInvalidGrantID, description)
		}
		return fmt.Errorf("%w: %w", ErrAuthorizationFailed, ErrInvalidGrantID)
	}
	if description != "" {
		return fmt.Errorf("%w: %s: %s", ErrAuthorizationFailed, code, description)
	}
	return fmt.Errorf("%w: %s", ErrAuthorizationFailed, code)
}

func (r *RP) providerForCallback(ctx context.Context, issuer string) (metadata.Provider, error) {
	provider := r.provider
	if !r.providerSet || provider.Issuer == "" {
		var err error
		provider, err = r.discoverProviderMetadata(ctx, issuer)
		if err != nil {
			return metadata.Provider{}, fmt.Errorf("%w: discovery failed: %v", ErrTokenExchangeFailed, err)
		}
	}
	if len(provider.TokenEndpointAuthMethodsSupported) > 0 {
		if err := r.applySupportedAuthMethods(provider.TokenEndpointAuthMethodsSupported); err != nil {
			return metadata.Provider{}, fmt.Errorf("%w: auth method negotiation failed: %v", ErrTokenExchangeFailed, err)
		}
	}
	return provider, nil
}

// HandleCallback validates callback state and performs token/userinfo processing.
func (r *RP) HandleCallback(w http.ResponseWriter, req *http.Request) (*CallbackResult, error) {
	ctx, span := r.spanStart(req.Context(), "rp.handle_callback",
		attribute.Bool("lanyard.jarm", r.isJARMResponse(extractCallbackParams(req))),
	)
	defer span.End()

	result, err := r.handleCallback(ctx, w, req)
	spanError(span, err)
	return result, err
}

func (r *RP) handleCallback(ctx context.Context, w http.ResponseWriter, req *http.Request) (*CallbackResult, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: missing callback request", ErrInvalidState)
	}

	params := extractCallbackParams(req)

	code, state, authzResponseIss, err := r.parseAuthorizationResponse(ctx, params)
	if err != nil {
		return nil, err
	}

	if state == "" {
		return nil, fmt.Errorf("%w: missing state", ErrInvalidState)
	}
	if code == "" {
		return nil, fmt.Errorf("%w", ErrMissingCode)
	}

	stateCtx, stateSpan := r.spanStart(ctx, "rp.state_validation")
	data, ok, err := r.stateStore.ConsumeCorrelation(stateCtx, w, req, state)
	if err != nil || !ok {
		stateSpan.SetStatus(codes.Error, safeSpanErrorDescription(ErrInvalidState))
	}
	stateSpan.End()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to consume state: %v", ErrInvalidState, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: unknown or expired state", ErrInvalidState)
	}
	if data.ClientID != "" {
		r.clientID = data.ClientID
	}
	if data.ClientSecret != "" {
		r.clientSecret = data.ClientSecret
	}
	if params.IDToken != "" {
		idToken := params.IDToken
		if strings.Count(params.IDToken, ".") == 4 {
			decrypted, _, err := r.decryptIDTokenIfNeeded(params.IDToken)
			if err != nil {
				return nil, err
			}
			idToken = decrypted
		}
		authzClaims, err := r.validateAuthorizationResponseIDToken(req.Context(), idToken, data.Nonce, code, state, r.provider.JWKSURI, r.provider.IDTokenSigningAlgValuesSupported)
		if err != nil {
			return nil, err
		}
		if authzResponseIss == "" {
			authzResponseIss = authzClaims.Issuer
		}
	}

	expectedIssuer := data.Issuer
	if expectedIssuer == "" {
		expectedIssuer = r.issuer
	}

	if r.validateAuthorizationResponseIssuer && authzResponseIss == "" {
		return nil, fmt.Errorf("%w: authorization response iss is required", ErrInvalidState)
	}

	if r.validateAuthorizationResponseIssuer && authzResponseIss != "" && authzResponseIss != expectedIssuer {
		return nil, fmt.Errorf("%w: authorization response iss mismatch", ErrInvalidState)
	}

	issuer := expectedIssuer
	r.issuer = issuer

	provider, err := r.providerForCallback(ctx, issuer)
	if err != nil {
		return nil, err
	}

	tokenEndpoint := r.tokenEndpoint(provider)
	if tokenEndpoint == "" {
		return nil, fmt.Errorf("%w: provider missing token endpoint", ErrTokenExchangeFailed)
	}

	tokenResp, err := r.exchangeTokenSpan(ctx, tokenEndpoint, code, data.CodeVerifier, data.Resources)
	if err != nil {
		return nil, err
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: token response missing access_token", ErrUserInfoValidationFailed)
	}

	if !r.usesOpenIDScope() {
		return &CallbackResult{
			AccessToken: tokenResp.AccessToken,
		}, nil
	}

	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("%w: token response missing id_token", ErrIDTokenValidationFailed)
	}

	claims, err := r.validateIDTokenSpan(ctx, tokenResp.IDToken, data.Nonce, provider.JWKSURI, provider.IDTokenSigningAlgValuesSupported)
	if err != nil {
		return nil, err
	}
	if r.isFAPIProfile() {
		return &CallbackResult{Subject: claims.Subject, AccessToken: tokenResp.AccessToken, GrantID: tokenResp.GrantID, Cnf: claims.Cnf, VerifiedClaims: parseIDTokenVerifiedClaims(claims)}, nil
	}

	userInfoEndpoint := r.userInfoEndpoint(provider)
	if userInfoEndpoint == "" {
		return nil, fmt.Errorf("%w: provider missing userinfo endpoint", ErrUserInfoValidationFailed)
	}

	transport := UserInfoTokenTransport(data.UserInfoTokenTransport)
	if transport == "" {
		transport = r.userInfoTokenTransport
	}

	userinfo, err := r.fetchUserInfoSpan(ctx, userInfoEndpoint, tokenResp.AccessToken, claims.Subject, transport)
	if err != nil {
		return nil, err
	}

	return &CallbackResult{Subject: claims.Subject, AccessToken: tokenResp.AccessToken, UserInfo: userinfo, GrantID: tokenResp.GrantID, Cnf: claims.Cnf, VerifiedClaims: parseIDTokenVerifiedClaims(claims)}, nil
}

// exchangeTokenSpan wraps the code-for-token exchange with a child span.
func (r *RP) exchangeTokenSpan(ctx context.Context, tokenEndpoint, code, verifier string, resources []string) (Token, error) {
	ctx, span := r.spanStart(ctx, "rp.token_exchange",
		attribute.String("lanyard.auth_method", string(r.resolvedAuthMethod)),
	)
	defer span.End()

	token, err := r.exchangeToken(ctx, tokenEndpoint, code, verifier, resources)
	spanError(span, err)
	return token, err
}

// validateIDTokenSpan wraps ID token validation with a child span. The token
// itself never enters telemetry; only algorithm identifiers do.
func (r *RP) validateIDTokenSpan(ctx context.Context, rawIDToken, expectedNonce, jwksURL string, providerAllowedAlgs []string) (idTokenClaims, error) {
	ctx, span := r.spanStart(ctx, "rp.id_token_validation")
	defer span.End()

	claims, err := r.validateIDToken(ctx, rawIDToken, expectedNonce, jwksURL, providerAllowedAlgs)
	spanError(span, err)
	return claims, err
}

// fetchUserInfoSpan wraps the userinfo request with a child span. The access
// token and response payload never enter telemetry.
func (r *RP) fetchUserInfoSpan(ctx context.Context, endpoint, accessToken, expectedSub string, transport UserInfoTokenTransport) (map[string]any, error) {
	ctx, span := r.spanStart(ctx, "rp.userinfo",
		attribute.String("lanyard.userinfo_transport", string(transport)),
	)
	defer span.End()

	payload, err := r.fetchUserInfo(ctx, endpoint, accessToken, expectedSub, transport)
	spanError(span, err)
	return payload, err
}

func parseIDTokenVerifiedClaims(claims idTokenClaims) []VerifiedClaims {
	if len(claims.VerifiedClaims) == 0 {
		return nil
	}
	parsed, err := parseVerifiedClaimsJSON(claims.VerifiedClaims)
	if err != nil {
		return nil
	}
	return parsed
}

func (r *RP) validateAuthorizationResponseIDToken(ctx context.Context, rawIDToken, expectedNonce, code, state, jwksURL string, providerAllowedAlgs []string) (idTokenClaims, error) {
	claims, err := r.validateIDToken(ctx, rawIDToken, expectedNonce, jwksURL, providerAllowedAlgs)
	if err != nil {
		return idTokenClaims{}, err
	}
	decrypted, _, err := r.decryptIDTokenIfNeeded(rawIDToken)
	if err != nil {
		return idTokenClaims{}, err
	}
	parsed, err := josejwt.ParseSigned(decrypted, supportedIDTokenAlgs)
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: parse authorization response id_token: %v", ErrIDTokenValidationFailed, err)
	}
	var rawClaims idTokenClaims
	if err := parsed.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: parse authorization response id_token claims: %v", ErrIDTokenValidationFailed, err)
	}
	alg := parsed.Headers[0].Algorithm
	if err := validateHashClaim(alg, code, rawClaims.CHash); err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: c_hash %v", ErrIDTokenValidationFailed, err)
	}
	if err := validateHashClaim(alg, state, rawClaims.SHash); err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: s_hash %v", ErrIDTokenValidationFailed, err)
	}
	if rawClaims.Iat != nil {
		iat := time.Unix(*rawClaims.Iat, 0).UTC()
		if iat.Before(r.now().Add(-r.clockSkew)) {
			return idTokenClaims{}, fmt.Errorf("%w: authorization response id_token iat too old", ErrIDTokenValidationFailed)
		}
	}
	return claims, nil
}

func (r *RP) isFAPIProfile() bool {
	return r.profile.isFAPI()
}

func (r *RP) usesOpenIDScope() bool {
	for _, scope := range r.scopes {
		if strings.EqualFold(strings.TrimSpace(scope), "openid") {
			return true
		}
	}
	return false
}
