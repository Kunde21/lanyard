package conformanceharness

import (
	"fmt"
	"sort"
	"strings"
)

type repeatableStringFlag []string

func (f *repeatableStringFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *repeatableStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func parseForcedVariants(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	parsed := make(map[string]string, len(raw))
	for _, entry := range raw {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}

		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			return nil, fmt.Errorf("invalid forced variant %q: expected key=value", entry)
		}

		variantName := strings.TrimSpace(key)
		variantValue := strings.TrimSpace(value)
		if variantName == "" || variantValue == "" {
			return nil, fmt.Errorf("invalid forced variant %q: key and value must be non-empty", entry)
		}

		parsed[variantName] = variantValue
	}

	if len(parsed) == 0 {
		return nil, nil
	}

	return parsed, nil
}

func mergePlanVariant(base, overrides map[string]string) map[string]string {
	if len(base) == 0 && len(overrides) == 0 {
		return nil
	}

	merged := make(map[string]string, len(base)+len(overrides))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overrides {
		merged[k] = v
	}

	if len(merged) == 0 {
		return nil
	}

	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	stable := make(map[string]string, len(merged))
	for _, k := range keys {
		stable[k] = merged[k]
	}

	return stable
}

func mergeModuleVariant(base map[string]any, overrides map[string]string) map[string]any {
	if len(base) == 0 && len(overrides) == 0 {
		return nil
	}

	merged := make(map[string]any, len(base)+len(overrides))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overrides {
		merged[k] = v
	}

	if len(merged) == 0 {
		return nil
	}

	return merged
}
