package k6fido

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"

	"fmt"
	"math/big"
)

// Conventional format of the ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

// Externally visible: Generates an ECDSA DER formatted key pair
func (k6fido *K6Fido) GenerateKeyPair() (string, string, error) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("Failed to generate private key: %v", err)
	}

	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("Failed to marshal private key: %v", err)
	}

	derPublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("Failed to marshal public key: %v", err)
	}

	return base64.StdEncoding.EncodeToString(derPrivateKey), base64.StdEncoding.EncodeToString(derPublicKey), nil
}

// Externally visible: Signs the passed signature data using the ECDSA DER formatted private key
func (k6fido *K6Fido) SignData(signatureData string, base64PrivateKey string) (string, error) {
	signatureDataBytes := []byte(signatureData)
	signedData, err := SignDataLocal(signatureDataBytes, base64PrivateKey)
	if err != nil {
		return "", fmt.Errorf("Failed to sign data: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signedData), nil
}

// Signs the passed signature data using the ECDSA DER formatted private key
func SignDataLocal(signatureData []byte, base64PrivateKey string) ([]byte, error) {
	derPrivateKey, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode base64 private key: %v", err)
	}

	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(derPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse PKCS8 private key: %v", err)
	}
	privateKey, ok := privateKeyInterface.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Could not assert privateKeyInterface to an *ecdsa.PrivateKey")
	}

	h := sha256.New()
	h.Write(signatureData)
	hash := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	// Create an ECDSASignature instance
	ecdsaSig := ECDSASignature{r, s}

	// Marshal the signature into ASN.1 DER form
	signature, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 DER marshal ECDSA signature: %v", err)
	}

	return signature, nil
}
