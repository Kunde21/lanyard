package rp

import (
	"fmt"
	"net/url"
	"strings"
)

func normalizeResources(resources []string) ([]string, error) {
	if len(resources) == 0 {
		return nil, nil
	}

	normalized := make([]string, 0, len(resources))
	for _, resource := range resources {
		trimmed := strings.TrimSpace(resource)
		if trimmed == "" {
			return nil, fmt.Errorf("%w: resource must not be empty", ErrInvalidConfiguration)
		}
		parsed, err := url.Parse(trimmed)
		if err != nil || !parsed.IsAbs() || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("%w: resource must be an absolute URI: %q", ErrInvalidConfiguration, resource)
		}
		if parsed.Fragment != "" {
			return nil, fmt.Errorf("%w: resource must not include a fragment: %q", ErrInvalidConfiguration, resource)
		}
		normalized = append(normalized, trimmed)
	}
	return normalized, nil
}

func addResourceParameters(values url.Values, resources []string) {
	for _, resource := range resources {
		values.Add("resource", resource)
	}
}
