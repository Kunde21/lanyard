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
	FAPIRequestMethod        string
	FAPIResponseMode         string
}

func expandMatrixVariants(matrixName, planName string) ([]matrixVariant, error) {
	if matrixName == "" || matrixName == "off" {
		return nil, nil
	}

	switch matrixName {
	case "fapi2-sp-final-plain-fapi-first4":
		if planName != "fapi2-security-profile-final-client-test-plan" {
			return nil, nil
		}
		return buildPlainFAPIMatrixVariants(false), nil
	case "fapi2-sp-final-plain-fapi-all16":
		if planName != "fapi2-security-profile-final-client-test-plan" {
			return nil, nil
		}
		return buildPlainFAPIMatrixVariants(true), nil
	case "fapi2-sp-final-plain-fapi-mtls":
		if planName != "fapi2-security-profile-final-client-test-plan" {
			return nil, nil
		}
		return buildPlainFAPIMTLSOnlyMatrixVariants(false), nil
	case "fapi2-ms-final-plain-fapi-jar4":
		if planName != "fapi2-message-signing-final-client-test-plan" {
			return nil, nil
		}
		return buildMessageSigningMatrixVariants(false, "plain_response"), nil
	case "fapi2-ms-final-plain-fapi-jarm4":
		if planName != "fapi2-message-signing-final-client-test-plan" {
			return nil, nil
		}
		return buildMessageSigningMatrixVariants(false, "jarm"), nil
	case "fapi2-ms-final-plain-fapi-all32":
		if planName != "fapi2-message-signing-final-client-test-plan" {
			return nil, nil
		}
		return buildMessageSigningMatrixVariants(true, ""), nil
	case "fapi1-adv-final-first4":
		if planName != "fapi1-advanced-final-client-test-plan" {
			return nil, nil
		}
		return buildFAPI1AdvancedMatrixVariants(false), nil
	case "fapi1-adv-final-all16":
		if planName != "fapi1-advanced-final-client-test-plan" {
			return nil, nil
		}
		return buildFAPI1AdvancedMatrixVariants(true), nil
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

func buildPlainFAPIMTLSOnlyMatrixVariants(includeAll bool) []matrixVariant {
	types := []string{"private_key_jwt", "mtls"}
	constrains := []string{"mtls"}
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
						Name:     fmt.Sprintf("plain-fapi-mtls-%02d", index),
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

func buildMessageSigningMatrixVariants(includeAll bool, fixedResponseMode string) []matrixVariant {
	types := []string{"private_key_jwt", "mtls"}
	constrains := []string{"mtls", "dpop"}
	requestTypes := []string{"simple"}
	clientTypes := []string{"oidc"}
	responseModes := []string{"plain_response"}
	if fixedResponseMode != "" {
		responseModes = []string{fixedResponseMode}
	}
	if includeAll {
		requestTypes = []string{"simple", "rar"}
		clientTypes = []string{"oidc", "plain_oauth"}
		responseModes = []string{"plain_response", "jarm"}
	}

	variants := make([]matrixVariant, 0, len(types)*len(constrains)*len(requestTypes)*len(clientTypes)*len(responseModes))
	index := 1
	for _, authType := range types {
		for _, constrain := range constrains {
			for _, requestType := range requestTypes {
				for _, clientType := range clientTypes {
					for _, respMode := range responseModes {
						variant := map[string]string{
							"client_auth_type":           authType,
							"sender_constrain":           constrain,
							"authorization_request_type": requestType,
							"fapi_client_type":           clientType,
							"fapi_profile":               "plain_fapi",
							"fapi_request_method":        "signed_non_repudiation",
							"fapi_response_mode":         respMode,
						}
						respLabel := respMode
						if respLabel == "plain_response" {
							respLabel = "plain"
						}
						variants = append(variants, matrixVariant{
							Name:     fmt.Sprintf("ms-plain-fapi-%s-%02d", respLabel, index),
							PlanName: "fapi2-message-signing-final-client-test-plan",
							Variant:  variant,
							RPProfile: RPProfileConfig{
								ClientAuthType:           authType,
								SenderConstrain:          constrain,
								AuthorizationRequestType: requestType,
								FAPIClientType:           clientType,
								FAPIProfile:              "plain_fapi",
								FAPIRequestMethod:        "signed_non_repudiation",
								FAPIResponseMode:         respMode,
							},
						})
						index++
					}
				}
			}
		}
	}

	return variants
}

func buildFAPI1AdvancedMatrixVariants(includeAll bool) []matrixVariant {
	authTypes := []string{"private_key_jwt", "mtls"}
	requestMethods := []string{"by_value"}
	clientTypes := []string{"oidc"}
	responseModes := []string{"plain_response", "jarm"}
	if includeAll {
		requestMethods = []string{"by_value", "pushed"}
		clientTypes = []string{"oidc", "plain_oauth"}
	}

	variants := make([]matrixVariant, 0, len(authTypes)*len(requestMethods)*len(clientTypes)*len(responseModes))
	index := 1
	for _, authType := range authTypes {
		for _, reqMethod := range requestMethods {
			for _, clientType := range clientTypes {
				for _, respMode := range responseModes {
					variant := map[string]string{
						"client_auth_type":         authType,
						"fapi_auth_request_method": reqMethod,
						"fapi_client_type":         clientType,
						"fapi_profile":             "plain_fapi",
						"fapi_response_mode":       respMode,
						"sender_constrain":         "mtls",
					}

					reqLabel := reqMethod
					if reqLabel == "by_value" {
						reqLabel = "byval"
					}
					respLabel := respMode
					if respLabel == "plain_response" {
						respLabel = "plain"
					}

					variants = append(variants, matrixVariant{
						Name:     fmt.Sprintf("fapi1-adv-%s-%s-%02d", reqLabel, respLabel, index),
						PlanName: "fapi1-advanced-final-client-test-plan",
						Variant:  variant,
						RPProfile: RPProfileConfig{
							ClientAuthType:   authType,
							SenderConstrain:  "mtls",
							FAPIClientType:   clientType,
							FAPIProfile:      "plain_fapi",
							FAPIResponseMode: respMode,
						},
					})
					index++
				}
			}
		}
	}

	return variants
}
