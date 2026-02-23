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
	"sort"
	"strings"
	"time"
)

type suiteClient struct {
	baseURL string
	http    *http.Client
}

func newSuiteClient(rawURL string) *suiteClient {
	return &suiteClient{
		baseURL: strings.TrimRight(rawURL, "/"),
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
			},
		},
	}
}

type AvailablePlan struct {
	Name      string              `json:"name"`
	Profile   string              `json:"profile"`
	Modules   []PlanModule        `json:"modules"`
	Variants  map[string][]string `json:"variants,omitempty"`
	RawConfig map[string]any      `json:"raw_config,omitempty"`
}

type PlanModule struct {
	Name    string         `json:"name"`
	Variant map[string]any `json:"variant,omitempty"`
}

type createdPlan struct {
	PlanID  string       `json:"plan_id"`
	Name    string       `json:"name"`
	Modules []PlanModule `json:"modules"`
}

type testInfo struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Result  string `json:"result"`
	Summary string `json:"summary"`
}

func (c *suiteClient) ListAvailablePlans(ctx context.Context) ([]AvailablePlan, error) {
	var payload any
	if err := c.doJSON(ctx, http.MethodGet, "/api/plan/available", nil, nil, &payload); err != nil {
		return nil, err
	}

	plans, err := parseAvailablePlans(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode available plans response: %w", err)
	}
	return plans, nil
}

func (c *suiteClient) CreatePlan(ctx context.Context, planName string, variant map[string]string, config map[string]any) (createdPlan, error) {
	query := url.Values{}
	query.Set("planName", planName)
	if len(variant) > 0 {
		encodedVariant, err := json.Marshal(variant)
		if err != nil {
			return createdPlan{}, fmt.Errorf("failed to encode plan variant: %w", err)
		}
		query.Set("variant", string(encodedVariant))
	}

	if config == nil {
		config = map[string]any{}
	}

	var payload any
	if err := c.doJSON(ctx, http.MethodPost, "/api/plan", query, config, &payload); err != nil {
		return createdPlan{}, err
	}

	plan := parseCreatedPlan(payload)
	if plan.PlanID == "" {
		return createdPlan{}, fmt.Errorf("create plan response missing plan id")
	}
	if plan.Name == "" {
		plan.Name = planName
	}
	return plan, nil
}

func (c *suiteClient) CreateTestInstance(ctx context.Context, testName, planID string, variant map[string]any, config map[string]any) (string, error) {
	query := url.Values{}
	query.Set("test", testName)
	if planID != "" {
		query.Set("plan", planID)
	}
	if len(variant) > 0 {
		encodedVariant, err := json.Marshal(variant)
		if err != nil {
			return "", fmt.Errorf("failed to encode test variant: %w", err)
		}
		query.Set("variant", string(encodedVariant))
	}

	var body any
	if planID == "" {
		if config == nil {
			config = map[string]any{}
		}
		body = config
	}

	var payload any
	if err := c.doJSON(ctx, http.MethodPost, "/api/runner", query, body, &payload); err != nil {
		return "", err
	}

	id := parseStringField(payload, "id", "testId", "test_id")
	if id == "" {
		return "", fmt.Errorf("create test response missing id")
	}
	return id, nil
}

func (c *suiteClient) GetTestInfo(ctx context.Context, testID string) (testInfo, error) {
	path := "/api/info/" + url.PathEscape(testID)
	var payload any
	if err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &payload); err != nil {
		return testInfo{}, err
	}
	info := parseTestInfo(payload)
	if info.ID == "" {
		info.ID = testID
	}
	return info, nil
}

func (c *suiteClient) StartTest(ctx context.Context, testID string) error {
	path := "/api/runner/" + url.PathEscape(testID)
	if err := c.doJSON(ctx, http.MethodPost, path, nil, nil, nil); err != nil {
		return err
	}
	return nil
}

func (c *suiteClient) ExportPlanZip(ctx context.Context, planID string) ([]byte, error) {
	path := "/api/plan/exporthtml/" + url.PathEscape(planID)
	endpoint := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to export plan zip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return nil, fmt.Errorf("export plan zip failed: status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading zip body: %w", err)
	}
	return data, nil
}

func (c *suiteClient) doJSON(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to encode request JSON: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return fmt.Errorf("suite API %s %s failed: status=%d body=%q", method, endpoint, resp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
		return fmt.Errorf("failed decoding JSON response: %w", err)
	}
	return nil
}

func parseAvailablePlans(payload any) ([]AvailablePlan, error) {
	list, ok := payload.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list response")
	}

	plans := make([]AvailablePlan, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := strings.TrimSpace(parseStringField(m, "planName", "name", "testPlanName"))
		if name == "" {
			continue
		}
		profile := strings.TrimSpace(parseStringField(m, "profile", "variant"))
		modules := parseModules(m)
		variants := parseVariants(m)
		plans = append(plans, AvailablePlan{Name: name, Profile: profile, Modules: modules, Variants: variants, RawConfig: m})
	}
	return plans, nil
}

func parseVariants(m map[string]any) map[string][]string {
	raw, ok := m["variants"]
	if !ok {
		return nil
	}
	variantsMap, ok := raw.(map[string]any)
	if !ok {
		return nil
	}

	result := make(map[string][]string, len(variantsMap))
	for variantName, rawVariantDef := range variantsMap {
		variantDef, ok := rawVariantDef.(map[string]any)
		if !ok {
			continue
		}
		rawValues, ok := variantDef["variantValues"].(map[string]any)
		if !ok {
			continue
		}
		values := make([]string, 0, len(rawValues))
		for valueName := range rawValues {
			values = append(values, valueName)
		}
		sort.Strings(values)
		result[variantName] = values
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func parseModules(m map[string]any) []PlanModule {
	for _, key := range []string{"testModules", "modules", "tests"} {
		raw, ok := m[key]
		if !ok {
			continue
		}
		arr, ok := raw.([]any)
		if !ok {
			continue
		}
		modules := make([]PlanModule, 0, len(arr))
		for _, item := range arr {
			switch typed := item.(type) {
			case map[string]any:
				name := parseStringField(typed, "testModule", "testName", "name", "module", "test")
				if name == "" {
					continue
				}
				module := PlanModule{Name: name}
				if rawVariant, ok := typed["variant"].(map[string]any); ok {
					module.Variant = rawVariant
				}
				modules = append(modules, module)
			case string:
				if strings.TrimSpace(typed) != "" {
					modules = append(modules, PlanModule{Name: strings.TrimSpace(typed)})
				}
			}
		}
		return modules
	}
	return nil
}

func parseCreatedPlan(payload any) createdPlan {
	m, ok := payload.(map[string]any)
	if !ok {
		return createdPlan{}
	}
	return createdPlan{
		PlanID:  parseStringField(m, "id", "planId", "plan_id"),
		Name:    parseStringField(m, "planName", "name"),
		Modules: parseModules(m),
	}
}

func parseTestInfo(payload any) testInfo {
	m, ok := payload.(map[string]any)
	if !ok {
		return testInfo{}
	}

	summary := parseStringField(m, "summary", "statusText")
	if summary == "" {
		summary = parseStringField(m, "displayName")
	}

	return testInfo{
		ID:      parseStringField(m, "id", "testId", "test_id"),
		Status:  strings.ToUpper(parseStringField(m, "status", "state")),
		Result:  strings.ToUpper(parseStringField(m, "result", "testResult")),
		Summary: summary,
	}
}

func parseStringField(value any, keys ...string) string {
	m, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range keys {
		if raw, found := m[key]; found {
			switch typed := raw.(type) {
			case string:
				if trimmed := strings.TrimSpace(typed); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}
