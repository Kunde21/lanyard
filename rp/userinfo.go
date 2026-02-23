package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func (r *RP) fetchUserInfo(ctx context.Context, endpoint, accessToken, expectedSub string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build userinfo request: %v", ErrUserInfoValidationFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	var payload map[string]any
	status, preview, err := doJSON(req, r.httpClient, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&payload)
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return nil, fmt.Errorf("%w: failed to decode userinfo JSON: %v", ErrUserInfoValidationFailed, decodeErr.Err)
		}
		return nil, fmt.Errorf("%w: failed to execute userinfo request: %v", ErrUserInfoValidationFailed, err)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: userinfo endpoint returned status %d: %s", ErrUserInfoValidationFailed, status, preview)
	}

	gotSub, _ := payload["sub"].(string)
	if gotSub == "" || gotSub != expectedSub {
		return nil, fmt.Errorf("%w: userinfo sub mismatch", ErrUserInfoValidationFailed)
	}

	return payload, nil
}
