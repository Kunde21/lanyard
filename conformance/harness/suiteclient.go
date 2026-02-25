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
	PlanID  string `json:"planId"`
	Alias   string `json:"alias"`
}

func (c *suiteClient) ListAvailablePlans(ctx context.Context) ([]AvailablePlan, error) {
	var payload json.RawMessage
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

	var payload json.RawMessage
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

type testInstance struct {
	ID string `json:"id"`
}

func (c *suiteClient) CreateTestInstance(ctx context.Context, testName, planID string, variant map[string]any, config map[string]any) (testInstance, error) {
	query := url.Values{}
	query.Set("test", testName)
	if planID != "" {
		query.Set("plan", planID)
	}
	if len(variant) > 0 {
		encodedVariant, err := json.Marshal(variant)
		if err != nil {
			return testInstance{}, fmt.Errorf("failed to encode test variant: %w", err)
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

	var payload json.RawMessage
	if err := c.doJSON(ctx, http.MethodPost, "/api/runner", query, body, &payload); err != nil {
		return testInstance{}, err
	}

	instance := testInstance{
		ID: parseStringField(payload, "id", "testId", "test_id"),
	}
	if instance.ID == "" {
		return testInstance{}, fmt.Errorf("create test response missing id")
	}
	return instance, nil
}

func (c *suiteClient) GetTestInfo(ctx context.Context, testID string) (testInfo, error) {
	path := "/api/info/" + url.PathEscape(testID)
	var payload json.RawMessage
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

func (c *suiteClient) CancelTest(ctx context.Context, testID string) error {
	path := "/api/runner/" + url.PathEscape(testID)
	if err := c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
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

func (c *suiteClient) doJSON(ctx context.Context, method, path string, query url.Values, body any, out *json.RawMessage) error {
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

func parseAvailablePlans(payload json.RawMessage) ([]AvailablePlan, error) {
	var list []json.RawMessage
	if err := json.Unmarshal(payload, &list); err != nil {
		return nil, fmt.Errorf("expected list response: %w", err)
	}

	plans := make([]AvailablePlan, 0, len(list))
	for _, item := range list {
		m := map[string]json.RawMessage{}
		if err := json.Unmarshal(item, &m); err != nil {
			continue
		}
		name := strings.TrimSpace(firstString(m, "planName", "name", "testPlanName"))
		if name == "" {
			continue
		}
		profile := strings.TrimSpace(firstString(m, "profile", "variant"))
		modules := parseModules(m)
		variants := parseVariants(m)
		var rawConfig map[string]any
		_ = json.Unmarshal(item, &rawConfig)
		plans = append(plans, AvailablePlan{Name: name, Profile: profile, Modules: modules, Variants: variants, RawConfig: rawConfig})
	}
	return plans, nil
}

func parseVariants(m map[string]json.RawMessage) map[string][]string {
	raw, ok := m["variants"]
	if !ok {
		return nil
	}
	variantsMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &variantsMap); err != nil {
		return nil
	}

	result := make(map[string][]string, len(variantsMap))
	for variantName, rawVariantDef := range variantsMap {
		variantDef := struct {
			VariantValues map[string]json.RawMessage `json:"variantValues"`
		}{}
		if err := json.Unmarshal(rawVariantDef, &variantDef); err != nil {
			continue
		}
		values := make([]string, 0, len(variantDef.VariantValues))
		for valueName := range variantDef.VariantValues {
			values = append(values, valueName)
		}
		if len(values) == 0 {
			continue
		}
		sort.Strings(values)
		result[variantName] = values
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func parseModules(m map[string]json.RawMessage) []PlanModule {
	for _, key := range []string{"testModules", "modules", "tests"} {
		raw, ok := m[key]
		if !ok || len(raw) == 0 {
			continue
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			continue
		}
		return parseModuleEntries(arr)
	}
	return nil
}

func parseModuleEntries(arr []json.RawMessage) []PlanModule {
	modules := make([]PlanModule, 0, len(arr))
	for _, raw := range arr {
		if module, ok := parseModuleEntry(raw); ok {
			modules = append(modules, module)
		}
	}
	return modules
}

func parseModuleEntry(raw json.RawMessage) (PlanModule, bool) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		trimmed := strings.TrimSpace(asString)
		if trimmed != "" {
			return PlanModule{Name: trimmed}, true
		}
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return PlanModule{}, false
	}
	name := firstString(fields, "testModule", "testName", "name", "module", "test")
	if name == "" {
		return PlanModule{}, false
	}
	module := PlanModule{Name: name}
	if variantRaw, ok := fields["variant"]; ok && len(variantRaw) > 0 {
		var variant map[string]any
		if err := json.Unmarshal(variantRaw, &variant); err == nil {
			module.Variant = variant
		}
	}
	return module, true
}

func parseCreatedPlan(payload json.RawMessage) createdPlan {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return createdPlan{}
	}
	return createdPlan{
		PlanID:  firstString(m, "id", "planId", "plan_id"),
		Name:    firstString(m, "planName", "name"),
		Modules: parseModules(m),
	}
}

func parseTestInfo(payload json.RawMessage) testInfo {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return testInfo{}
	}

	summary := firstString(m, "summary", "statusText")
	if summary == "" {
		summary = firstString(m, "displayName")
	}

	return testInfo{
		ID:      firstString(m, "id", "testId", "test_id"),
		Status:  strings.ToUpper(firstString(m, "status", "state")),
		Result:  strings.ToUpper(firstString(m, "result", "testResult")),
		Summary: summary,
		PlanID:  firstString(m, "planId", "plan_id"),
		Alias:   firstString(m, "alias"),
	}
}

func firstString(m map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		if raw, found := m[key]; found {
			var str string
			if err := json.Unmarshal(raw, &str); err == nil {
				if trimmed := strings.TrimSpace(str); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}

func parseStringField(raw json.RawMessage, keys ...string) string {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	return firstString(m, keys...)
}
