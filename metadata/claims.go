package metadata

import (
	"encoding/json"
	"errors"
)

var errClaimsNotAvailable = errors.New("claims not available")

// Claims unmarshals the raw provider JSON into dst.
func (p Provider) Claims(dst any) error {
	if len(p.Raw) == 0 {
		return errClaimsNotAvailable
	}

	if err := json.Unmarshal(p.Raw, dst); err != nil {
		return err
	}

	return nil
}

// Claims unmarshals the raw authorization server JSON into dst.
func (a AuthorizationServer) Claims(dst any) error {
	if len(a.Raw) == 0 {
		fallback, err := json.Marshal(a)
		if err != nil {
			return err
		}
		return json.Unmarshal(fallback, dst)
	}

	if err := json.Unmarshal(a.Raw, dst); err != nil {
		return err
	}

	return nil
}
