package rp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (r *RP) fetchUserInfo(ctx context.Context, endpoint, accessToken, expectedSub string, transport UserInfoTokenTransport) (map[string]any, error) {
	req, err := buildUserInfoRequest(ctx, endpoint, accessToken, transport)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserInfoValidationFailed, err)
	}

	useDPoP := transport == UserInfoTokenTransportHeader && r.shouldUseDPoP()
	if useDPoP {
		req.Header.Set("Authorization", "DPoP "+accessToken)
		cachedNonce := r.cachedDPoPNonce(endpoint)
		if err := r.attachDPoPProof(req, accessToken, cachedNonce); err != nil {
			return nil, fmt.Errorf("%w: failed to generate DPoP proof: %v", ErrUserInfoValidationFailed, err)
		}
	}

	var payload map[string]any
	resp, status, preview, err := doJSONStatus(req, r.httpClient, http.StatusOK, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&payload)
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return nil, fmt.Errorf("%w: failed to decode userinfo JSON: %v", ErrUserInfoValidationFailed, decodeErr.Err)
		}
		return nil, fmt.Errorf("%w: failed to execute userinfo request: %v", ErrUserInfoValidationFailed, err)
	}

	if useDPoP && resp != nil {
		r.extractAndStoreDPoPNonce(resp, endpoint)
	}

	if useDPoP && isUseDPoPNonce(resp) {
		nonce, ok := extractDPoPNonce(resp)
		if ok {
			retryReq, err := buildUserInfoRequest(ctx, endpoint, accessToken, transport)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrUserInfoValidationFailed, err)
			}
			retryReq.Header.Set("Authorization", "DPoP "+accessToken)
			if err := r.attachDPoPProof(retryReq, accessToken, nonce); err != nil {
				return nil, fmt.Errorf("%w: failed to generate DPoP proof: %v", ErrUserInfoValidationFailed, err)
			}

			resp, status, preview, err = doJSONStatus(retryReq, r.httpClient, http.StatusOK, func(body io.Reader) error {
				return json.NewDecoder(body).Decode(&payload)
			})
			if err != nil {
				var decodeErr *jsonDecodeError
				if errors.As(err, &decodeErr) {
					return nil, fmt.Errorf("%w: failed to decode userinfo JSON: %v", ErrUserInfoValidationFailed, decodeErr.Err)
				}
				return nil, fmt.Errorf("%w: failed to execute userinfo request: %v", ErrUserInfoValidationFailed, err)
			}
			if err == nil && resp != nil {
				r.extractAndStoreDPoPNonce(resp, endpoint)
			}
			if status != http.StatusOK {
				return nil, fmt.Errorf("%w: userinfo endpoint returned status %d: %s", ErrUserInfoValidationFailed, status, preview)
			}
		}
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: userinfo endpoint returned status %d: %s", ErrUserInfoValidationFailed, status, preview)
	}
	if payload == nil {
		return nil, fmt.Errorf("%w: userinfo response was empty", ErrUserInfoValidationFailed)
	}

	payload, err = r.resolveDistributedClaims(ctx, payload, expectedSub)
	if err != nil {
		return nil, err
	}

	gotSub, _ := payload["sub"].(string)
	if gotSub == "" || gotSub != expectedSub {
		return nil, fmt.Errorf("%w: userinfo sub mismatch", ErrUserInfoValidationFailed)
	}

	return payload, nil
}

func buildUserInfoRequest(ctx context.Context, endpoint, accessToken string, transport UserInfoTokenTransport) (*http.Request, error) {
	transport = normalizeUserInfoTokenTransport(transport)

	switch transport {
	case UserInfoTokenTransportBody:
		form := url.Values{}
		form.Set("access_token", accessToken)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("failed to build userinfo request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	case UserInfoTokenTransportHeader:
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build userinfo request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return req, nil
	default:
		return nil, fmt.Errorf("unsupported userinfo token transport %q", transport)
	}
}

func (r *RP) resolveDistributedClaims(ctx context.Context, payload map[string]any, expectedSub string) (map[string]any, error) {
	rawClaimNames, hasClaimNames := payload["_claim_names"]
	rawClaimSources, hasClaimSources := payload["_claim_sources"]
	if !hasClaimNames || !hasClaimSources {
		return payload, nil
	}

	claimNames, ok := rawClaimNames.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: _claim_names has invalid shape", ErrUserInfoValidationFailed)
	}
	claimSources, ok := rawClaimSources.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: _claim_sources has invalid shape", ErrUserInfoValidationFailed)
	}

	resolved := make(map[string]map[string]any, len(claimSources))
	for claimName, rawSourceName := range claimNames {
		sourceName, ok := rawSourceName.(string)
		if !ok || strings.TrimSpace(sourceName) == "" {
			return nil, fmt.Errorf("%w: _claim_names entry %q has invalid source reference", ErrUserInfoValidationFailed, claimName)
		}

		sourceClaims, found := resolved[sourceName]
		if !found {
			rawSource, ok := claimSources[sourceName]
			if !ok {
				return nil, fmt.Errorf("%w: claim source %q not found", ErrUserInfoValidationFailed, sourceName)
			}

			sourceDef, ok := rawSource.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: claim source %q has invalid shape", ErrUserInfoValidationFailed, sourceName)
			}

			fetched, err := r.fetchDistributedClaimSource(ctx, sourceDef, expectedSub)
			if err != nil {
				return nil, err
			}
			resolved[sourceName] = fetched
			sourceClaims = fetched
		}

		if claimValue, exists := sourceClaims[claimName]; exists {
			payload[claimName] = claimValue
		}
	}

	delete(payload, "_claim_names")
	delete(payload, "_claim_sources")

	return payload, nil
}

func (r *RP) fetchDistributedClaimSource(ctx context.Context, sourceDef map[string]any, expectedSub string) (map[string]any, error) {
	if rawJWT, ok := sourceDef["JWT"].(string); ok && strings.TrimSpace(rawJWT) != "" {
		claims, err := parseJWTClaims(strings.TrimSpace(rawJWT))
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse distributed claims JWT: %v", ErrUserInfoValidationFailed, err)
		}
		if err := validateClaimSubject(claims, expectedSub); err != nil {
			return nil, err
		}
		return claims, nil
	}

	endpoint, _ := sourceDef["endpoint"].(string)
	if strings.TrimSpace(endpoint) == "" {
		return nil, fmt.Errorf("%w: claim source missing endpoint and JWT", ErrUserInfoValidationFailed)
	}

	token, _ := sourceDef["access_token"].(string)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build distributed claims request: %v", ErrUserInfoValidationFailed, err)
	}
	req.Header.Set("Accept", "application/json, application/jwt")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to execute distributed claims request: %v", ErrUserInfoValidationFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: failed reading distributed claims response: %v", ErrUserInfoValidationFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		preview := string(bytes.TrimSpace(body))
		if len(preview) > maxErrorBodyBytes {
			preview = preview[:maxErrorBodyBytes]
		}
		return nil, fmt.Errorf("%w: distributed claims endpoint returned status %d: %s", ErrUserInfoValidationFailed, resp.StatusCode, preview)
	}

	claims, err := decodeDistributedClaims(body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode distributed claims response: %v", ErrUserInfoValidationFailed, err)
	}
	if err := validateClaimSubject(claims, expectedSub); err != nil {
		return nil, err
	}

	return claims, nil
}

func decodeDistributedClaims(body []byte) (map[string]any, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty distributed claims response")
	}

	if trimmed[0] == '{' {
		var claims map[string]any
		if err := json.Unmarshal(trimmed, &claims); err != nil {
			return nil, err
		}
		return claims, nil
	}

	return parseJWTClaims(string(trimmed))
}

func parseJWTClaims(rawJWT string) (map[string]any, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("jwt has invalid format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to base64url decode jwt payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse jwt claims JSON: %w", err)
	}

	return claims, nil
}

func validateClaimSubject(claims map[string]any, expectedSub string) error {
	if claims == nil {
		return fmt.Errorf("%w: distributed claims response was empty", ErrUserInfoValidationFailed)
	}
	if rawSub, ok := claims["sub"]; ok {
		sub, ok := rawSub.(string)
		if !ok || strings.TrimSpace(sub) == "" || sub != expectedSub {
			return fmt.Errorf("%w: distributed claims sub mismatch", ErrUserInfoValidationFailed)
		}
	}
	return nil
}
