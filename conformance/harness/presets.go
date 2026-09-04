package conformanceharness

import "fmt"

type presetConfig struct {
	Profile            string
	Matrices           []string
	Parallel           bool
	MaxParallelRuns    int
	IncludePlanRegex   string
	ExcludePlanRegex   string
	ExcludeModuleRegex string
}

var builtInPresets = map[string]presetConfig{
	"all-rp-full": {
		Profile: "all-rp",
		Matrices: []string{
			"oidcc-config-cert-all42",
			"fapi2-sp-final-plain-fapi-all16",
			"fapi2-ms-final-plain-fapi-all32",
			"fapi1-adv-final-all12",
		},
		Parallel:         true,
		MaxParallelRuns:  12,
		ExcludePlanRegex: "ciba|brazil|id1-|id2-|client-credentials",
	},
	"all-rp-smoke": {
		Profile: "all-rp",
		Matrices: []string{
			"oidcc-config-cert-first2",
			"fapi2-sp-final-plain-fapi-first4",
			"fapi2-ms-final-plain-fapi-jar4",
			"fapi1-adv-final-first4",
		},
		Parallel:        true,
		MaxParallelRuns: 4,
	},
	"fapi2-sp-full": {
		Profile:          "fapi-rp",
		Matrices:         []string{"fapi2-sp-final-plain-fapi-all16"},
		IncludePlanRegex: "fapi2-security-profile-final-client-test-plan",
		Parallel:         true,
		MaxParallelRuns:  8,
	},
	"fapi2-ms-full": {
		Profile:          "fapi-rp",
		Matrices:         []string{"fapi2-ms-final-plain-fapi-all32"},
		IncludePlanRegex: "fapi2-message-signing-final-client-test-plan",
		Parallel:         true,
		MaxParallelRuns:  8,
	},
	"fapi1-adv-full": {
		Profile:          "fapi-rp",
		Matrices:         []string{"fapi1-adv-final-all12"},
		IncludePlanRegex: "fapi1-advanced-final-client-test-plan",
		Parallel:         true,
		MaxParallelRuns:  8,
	},
	"fapi1-adv-smoke": {
		Profile:          "fapi-rp",
		Matrices:         []string{"fapi1-adv-final-first4"},
		IncludePlanRegex: "fapi1-advanced-final-client-test-plan",
		Parallel:         true,
		MaxParallelRuns:  4,
	},
	"oidcc-config-full": {
		Profile:          "oidc-rp",
		Matrices:         []string{"oidcc-config-cert-all42"},
		IncludePlanRegex: "oidcc-client-config-certification-test-plan",
		Parallel:         true,
		MaxParallelRuns:  8,
	},
	"oidcc-config-smoke": {
		Profile:          "oidc-rp",
		Matrices:         []string{"oidcc-config-cert-first2"},
		IncludePlanRegex: "oidcc-client-config-certification-test-plan",
		Parallel:         true,
		MaxParallelRuns:  2,
	},
	"oidcc-dynamic-full": {
		Profile:            "oidc-rp",
		Matrices:           []string{"oidcc-dynamic-cert"},
		IncludePlanRegex:   "oidcc-client-dynamic-certification-test-plan",
		ExcludeModuleRegex: "oidcc-client-test-request-uri-signed-(rs256|none)",
		Parallel:           true,
		MaxParallelRuns:    2,
	},
}

func resolvePreset(name string) (presetConfig, error) {
	cfg, ok := builtInPresets[name]
	if !ok {
		return presetConfig{}, fmt.Errorf("unknown preset %q (available: all-rp-full, all-rp-smoke, fapi2-sp-full, fapi2-ms-full, fapi1-adv-full, fapi1-adv-smoke, oidcc-config-full, oidcc-config-smoke, oidcc-dynamic-full)", name)
	}
	return cfg, nil
}
