package oidc

import (
	"encoding/json"
	"errors"
)

var errClaimsNotAvailable = errors.New("claims not available")

// Claims unmarshals the raw provider metadata JSON into dst.
func (m ProviderMetadata) Claims(dst any) error {
	if len(m.Raw) == 0 {
		return errClaimsNotAvailable
	}

	if err := json.Unmarshal(m.Raw, dst); err != nil {
		return err
	}

	return nil
}

// Claims unmarshals the raw authorization server metadata JSON into dst.
func (m AuthorizationServerMetadata) Claims(dst any) error {
	if len(m.Raw) == 0 {
		fallback, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return json.Unmarshal(fallback, dst)
	}

	if err := json.Unmarshal(m.Raw, dst); err != nil {
		return err
	}

	return nil
}
