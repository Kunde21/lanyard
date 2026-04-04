package rp

import (
	"net/http"
	"strings"
)

type callbackParams struct {
	Code             string
	State            string
	Iss              string
	Error            string
	ErrorDescription string
}

func extractCallbackParams(req *http.Request) callbackParams {
	params := callbackParams{}

	if req.Method == http.MethodPost && strings.HasPrefix(strings.TrimSpace(req.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		if err := req.ParseForm(); err == nil {
			params.Code = strings.TrimSpace(req.FormValue("code"))
			params.State = strings.TrimSpace(req.FormValue("state"))
			params.Iss = strings.TrimSpace(req.FormValue("iss"))
			params.Error = strings.TrimSpace(req.FormValue("error"))
			params.ErrorDescription = strings.TrimSpace(req.FormValue("error_description"))
			return params
		}
	}

	query := req.URL.Query()
	params.Code = strings.TrimSpace(query.Get("code"))
	params.State = strings.TrimSpace(query.Get("state"))
	params.Iss = strings.TrimSpace(query.Get("iss"))
	params.Error = strings.TrimSpace(query.Get("error"))
	params.ErrorDescription = strings.TrimSpace(query.Get("error_description"))

	return params
}

func (p callbackParams) AuthorizationError() (string, string) {
	return p.Error, p.ErrorDescription
}
