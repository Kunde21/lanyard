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
	_, status, preview, err := doJSONStatus(req, client, http.StatusOK, decoder)
	return status, preview, err
}

func doJSONStatus(req *http.Request, client *http.Client, successStatus int, decoder func(io.Reader) error) (*http.Response, int, string, error) {
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != successStatus {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return resp, resp.StatusCode, strings.TrimSpace(string(preview)), nil
	}

	if decoder != nil {
		if err := decoder(resp.Body); err != nil {
			return resp, resp.StatusCode, "", &jsonDecodeError{Err: err}
		}
	}

	return resp, resp.StatusCode, "", nil
}
