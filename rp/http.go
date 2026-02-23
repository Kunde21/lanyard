package rp

import (
	"io"
	"net/http"
	"strings"
)

const maxErrorBodyBytes = 4096

type jsonDecodeError struct {
	Err error
}

func (e *jsonDecodeError) Error() string { return e.Err.Error() }

func (e *jsonDecodeError) Unwrap() error { return e.Err }

func doJSON(req *http.Request, client *http.Client, decoder func(io.Reader) error) (int, string, error) {
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return resp.StatusCode, strings.TrimSpace(string(preview)), nil
	}

	if decoder != nil {
		if err := decoder(resp.Body); err != nil {
			return resp.StatusCode, "", &jsonDecodeError{Err: err}
		}
	}

	return resp.StatusCode, "", nil
}
