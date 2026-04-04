package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const webFingerIssuerRel = "http://openid.net/specs/connect/1.0/issuer"

type webFingerResponse struct {
	Subject string          `json:"subject"`
	Links   []webFingerLink `json:"links"`
}

type webFingerLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// DiscoverProviderFromResource resolves issuer from WebFinger and then runs provider discovery.
func (c *Client) DiscoverProviderFromResource(ctx context.Context, resource string) (Provider, error) {
	issuer, err := c.ResolveIssuerFromWebFinger(ctx, resource)
	if err != nil {
		return Provider{}, err
	}

	provider, err := c.DiscoverProvider(ctx, issuer)
	if err != nil {
		return Provider{}, err
	}

	return provider, nil
}

// ResolveIssuerFromWebFinger resolves an OIDC issuer from a WebFinger resource.
func (c *Client) ResolveIssuerFromWebFinger(ctx context.Context, resource string) (string, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", fmt.Errorf("%w: webfinger resource is required", ErrDiscoveryFailed)
	}

	host, err := webFingerHostFromResource(resource)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}

	endpoint := url.URL{Scheme: "https", Host: host, Path: "/.well-known/webfinger"}
	query := endpoint.Query()
	query.Set("resource", resource)
	query.Set("rel", webFingerIssuerRel)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("%w: failed to build webfinger request: %w", ErrDiscoveryFailed, err)
	}
	req.Header.Set("Accept", "application/jrd+json, application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: failed to execute webfinger request: %w", ErrDiscoveryFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return "", fmt.Errorf("%w: %w", ErrDiscoveryFailed, &HTTPStatusError{URL: endpoint.String(), StatusCode: resp.StatusCode, BodyPreview: strings.TrimSpace(string(preview))})
	}

	var payload webFingerResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("%w: failed to decode webfinger response: %w", ErrDiscoveryFailed, err)
	}

	for _, link := range payload.Links {
		if !strings.EqualFold(strings.TrimSpace(link.Rel), webFingerIssuerRel) {
			continue
		}

		href := strings.TrimSpace(link.Href)
		if href == "" {
			continue
		}
		if _, err := validateIssuerURL(href); err != nil {
			return "", fmt.Errorf("%w: invalid webfinger issuer link: %w", ErrDiscoveryFailed, err)
		}
		return href, nil
	}

	return "", fmt.Errorf("%w: webfinger response did not include %q issuer link", ErrDiscoveryFailed, webFingerIssuerRel)
}

func webFingerHostFromResource(resource string) (string, error) {
	if strings.HasPrefix(strings.ToLower(resource), "acct:") {
		account := strings.TrimPrefix(resource, "acct:")
		at := strings.LastIndex(account, "@")
		if at <= 0 || at+1 >= len(account) {
			return "", fmt.Errorf("invalid acct resource %q", resource)
		}
		host := strings.TrimSpace(account[at+1:])
		if host == "" {
			return "", fmt.Errorf("invalid acct resource %q", resource)
		}
		if _, err := url.Parse("https://" + host); err != nil {
			return "", fmt.Errorf("invalid acct host %q: %w", host, err)
		}
		return host, nil
	}

	parsed, err := url.Parse(resource)
	if err != nil {
		return "", fmt.Errorf("invalid webfinger resource %q: %w", resource, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") || strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("webfinger URL resource must be an absolute https URL")
	}

	return parsed.Host, nil
}
