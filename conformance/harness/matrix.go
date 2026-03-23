package conformanceharness

import "fmt"

type matrixVariant struct {
	Name      string
	PlanName  string
	Variant   map[string]string
	RPProfile RPProfileConfig
}

type RPProfileConfig struct {
	ClientAuthType           string
	SenderConstrain          string
	AuthorizationRequestType string
	FAPIClientType           string
	FAPIProfile              string
}

func expandMatrixVariants(matrixName, planName string) ([]matrixVariant, error) {
	if matrixName == "" || matrixName == "off" {
		return nil, nil
	}
	if planName != "fapi2-security-profile-final-client-test-plan" {
		return nil, nil
	}

	switch matrixName {
	case "fapi2-sp-final-plain-fapi-first4":
		return buildPlainFAPIMatrixVariants(false), nil
	case "fapi2-sp-final-plain-fapi-all16":
		return buildPlainFAPIMatrixVariants(true), nil
	default:
		return nil, fmt.Errorf("unknown matrix %q", matrixName)
	}
}

func buildPlainFAPIMatrixVariants(includeAll bool) []matrixVariant {
	types := []string{"private_key_jwt", "mtls"}
	constrains := []string{"mtls", "dpop"}
	requestTypes := []string{"simple"}
	clientTypes := []string{"oidc"}
	if includeAll {
		requestTypes = []string{"simple", "rar"}
		clientTypes = []string{"oidc", "plain_oauth"}
	}

	variants := make([]matrixVariant, 0, len(types)*len(constrains)*len(requestTypes)*len(clientTypes))
	index := 1
	for _, authType := range types {
		for _, constrain := range constrains {
			for _, requestType := range requestTypes {
				for _, clientType := range clientTypes {
					variant := map[string]string{
						"client_auth_type":           authType,
						"sender_constrain":           constrain,
						"authorization_request_type": requestType,
						"fapi_client_type":           clientType,
						"fapi_profile":               "plain_fapi",
					}
					variants = append(variants, matrixVariant{
						Name:     fmt.Sprintf("plain-fapi-%02d", index),
						PlanName: "fapi2-security-profile-final-client-test-plan",
						Variant:  variant,
						RPProfile: RPProfileConfig{
							ClientAuthType:           authType,
							SenderConstrain:          constrain,
							AuthorizationRequestType: requestType,
							FAPIClientType:           clientType,
							FAPIProfile:              "plain_fapi",
						},
					})
					index++
				}
			}
		}
	}

	return variants
}
