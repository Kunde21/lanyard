package rp

import (
	"errors"
	"fmt"
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

	resp, err := doSensitiveRequest(client, req)
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

// errInsecureRedirect reports a credential-bearing request being redirected
// insecurely; the body (secrets included) is never replayed to the target.
var errInsecureRedirect = errors.New("sensitive request redirect rejected")

// doSensitiveRequest executes an OAuth request that may carry credentials
// (client secrets, assertions, refresh tokens, authorization codes) under a
// redirect policy that refuses scheme downgrades and cross-origin redirects
// (fourth RC review R2): an endpoint answering 307/308 toward http:// or a
// different host never receives the request body.
func doSensitiveRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	checked := *client
	checked.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		previous := via[len(via)-1]
		if previous.URL.Scheme == "https" && next.URL.Scheme != "https" {
			return fmt.Errorf("%w: %s redirects from https to %s", errInsecureRedirect, previous.URL, next.URL.Scheme)
		}
		if next.URL.Host != previous.URL.Host {
			return fmt.Errorf("%w: %s redirects to different origin %s", errInsecureRedirect, previous.URL.Host, next.URL.Host)
		}
		return nil
	}
	return checked.Do(req)
}
