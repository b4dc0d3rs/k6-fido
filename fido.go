package k6fido

import (
	"encoding/json"
	"fmt"
)

type SendUafResponse struct {
	UafResponse string `json:"uafResponse"`
	Context     string `json:"context"`
}

// Externally visible: Generates Fido Registration Response
func (k6fido *K6Fido) GenerateRegistrationResponse(aaid string, uafRequest string,
	trustedFacetId string, overriddenSignature string, signatureSignData string,
	privKey string, pubKey string, keyId string) (string, error) {

	fidoRegistrationUafRequest := NewFidoRegistrationReturnUafRequest(uafRequest)

	fidoRegistrationResponse := FidoRegistrationResponse{
		facetId:          trustedFacetId,
		returnUafRequest: *fidoRegistrationUafRequest,
	}

	sendUafResponse, err := fidoRegistrationResponse.Build(aaid, overriddenSignature, signatureSignData, privKey, pubKey, keyId)
	if err != nil {
		return "", fmt.Errorf("Failed to build registration response: %v", err)
	}

	fidoRegistrationResponseString, err := json.Marshal(sendUafResponse)
	if err != nil {
		return "", fmt.Errorf("Failed to unmarshall ufa response: %v", err)
	}

	return string(fidoRegistrationResponseString), nil
}

// Externally visible: Generates Fido Authentication Response
func (k6fido *K6Fido) GenerateAuthenticationResponse(aaid string, uafRequest string,
	trustedFacetId string, overriddenSignature string, signatureSignData string,
	privKey string, pubKey string, username string, keyId string) (string, error) {

	fidoAuthenticationUafRequest := NewFidoAuthenticationReturnUafRequest(uafRequest)

	fidoAuthenticationResponse := FidoAuthenticationResponse{
		facetId:          trustedFacetId,
		returnUafRequest: *fidoAuthenticationUafRequest,
		username:         username,
	}

	sendUafResponse, err := fidoAuthenticationResponse.Build(aaid, overriddenSignature, signatureSignData, privKey, pubKey, keyId)
	if err != nil {
		return "", fmt.Errorf("Failed to build authentication response: %v", err)
	}

	fidoRegistrationResponseString, err := json.Marshal(sendUafResponse)
	if err != nil {
		return "", fmt.Errorf("Failed to marshall send ufa response: %v", err)
	}
	return string(fidoRegistrationResponseString), nil
}
