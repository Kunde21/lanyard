package conformanceharness

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Kunde21/lanyard/rp"
)

type rpRuntimeRequest struct {
	Alias                    string                    `json:"alias"`
	Issuer                   string                    `json:"issuer,omitempty"`
	ClientID                 string                    `json:"client_id"`
	ClientSecret             string                    `json:"client_secret,omitempty"`
	RedirectURI              string                    `json:"redirect_uri"`
	Scopes                   []string                  `json:"scopes,omitempty"`
	Namespace                string                    `json:"namespace,omitempty"`
	UserInfoTokenTransport   rp.UserInfoTokenTransport `json:"userinfo_token_transport,omitempty"`
	ClientAuthType           string                    `json:"client_auth_type,omitempty"`
	SenderConstrain          string                    `json:"sender_constrain,omitempty"`
	AuthorizationRequestType string                    `json:"authorization_request_type,omitempty"`
	FAPIClientType           string                    `json:"fapi_client_type,omitempty"`
	FAPIProfile              string                    `json:"fapi_profile,omitempty"`
	RequestType              string                    `json:"request_type,omitempty"`
	RequirePAR               bool                      `json:"require_par,omitempty"`
	ResponseMode             string                    `json:"response_mode,omitempty"`
	FAPIRequestMethod        string                    `json:"fapi_request_method,omitempty"`
	FAPIResponseMode         string                    `json:"fapi_response_mode,omitempty"`
}

type rpRuntimeClient interface {
	Register(ctx context.Context, req rpRuntimeRequest) error
	Delete(ctx context.Context, alias string) error
}

type httpRPRuntimeClient struct {
	baseURL string
	http    *http.Client
}

func newRPRuntimeClient(rawURL string) *httpRPRuntimeClient {
	return &httpRPRuntimeClient{
		baseURL: strings.TrimRight(rawURL, "/"),
		http: &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}},
		},
	}
}

func (c *httpRPRuntimeClient) Register(ctx context.Context, req rpRuntimeRequest) error {
	endpoint := c.baseURL + "/conformance/runtime"
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal runtime request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build runtime register request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("register runtime request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return fmt.Errorf("register runtime failed: status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *httpRPRuntimeClient) Delete(ctx context.Context, alias string) error {
	query := url.Values{}
	query.Set("alias", alias)
	endpoint := c.baseURL + "/conformance/runtime?" + query.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build runtime delete request: %w", err)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("delete runtime request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return fmt.Errorf("delete runtime failed: status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func buildRPRuntimeRequest(job RunJob, planVariant map[string]string, suiteURL string) rpRuntimeRequest {
	return buildRPRuntimeRequestForAlias(job, planVariant, suiteURL, job.Alias)
}

func scopesForPlanVariant(planVariant map[string]string) []string {
	if strings.EqualFold(strings.TrimSpace(planVariant["fapi_client_type"]), "plain_oauth") {
		return []string{"accounts"}
	}
	if isFAPI2PlanVariant(planVariant) {
		return []string{"openid"}
	}
	return []string{"openid", "profile", "email", "phone", "address"}
}

func responseModeForPlan(planName string) string {
	if strings.Contains(strings.ToLower(planName), "formpost") {
		return "form_post"
	}
	return ""
}

func responseModeForVariant(planVariant map[string]string) string {
	mode := strings.ToLower(strings.TrimSpace(planVariant["fapi_response_mode"]))
	if mode == "jarm" {
		return "query.jwt"
	}
	return ""
}

func coalesceResponseMode(planMode, variantMode string) string {
	if variantMode != "" {
		return variantMode
	}
	return planMode
}

func requirePARForVariant(planVariant map[string]string) bool {
	if v, ok := planVariant["fapi_auth_request_method"]; ok {
		return strings.EqualFold(strings.TrimSpace(v), "pushed")
	}
	return isFAPI2PlanVariant(planVariant)
}

func buildRPRuntimeRequestForAlias(job RunJob, planVariant map[string]string, suiteURL, alias string) rpRuntimeRequest {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		alias = job.Alias
	}
	requestType := requestTypeForPlanVariant(planVariant)
	clientID := "local-dev-client"
	clientSecret := "local-dev-secret-32-bytes-minimum!!"
	redirectURI := runtimeRedirectURI(alias)
	transport := rp.UserInfoTokenTransportHeader
	if strings.Contains(strings.ToLower(job.PlanName), "userinfo-bearer-body") {
		transport = rp.UserInfoTokenTransportBody
	}
	scopes := scopesForPlanVariant(planVariant)

	return rpRuntimeRequest{
		Alias:                    alias,
		Issuer:                   constructIssuer(suiteURL, "", alias),
		ClientID:                 clientID,
		ClientSecret:             clientSecret,
		RedirectURI:              redirectURI,
		Scopes:                   scopes,
		Namespace:                alias,
		UserInfoTokenTransport:   transport,
		ClientAuthType:           planVariant["client_auth_type"],
		SenderConstrain:          planVariant["sender_constrain"],
		AuthorizationRequestType: planVariant["authorization_request_type"],
		FAPIClientType:           planVariant["fapi_client_type"],
		FAPIProfile:              planVariant["fapi_profile"],
		RequestType:              requestType,
		RequirePAR:               requirePARForVariant(planVariant),
		ResponseMode:             coalesceResponseMode(responseModeForPlan(job.PlanName), responseModeForVariant(planVariant)),
		FAPIRequestMethod:        planVariant["fapi_request_method"],
		FAPIResponseMode:         planVariant["fapi_response_mode"],
	}
}
