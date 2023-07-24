package k6fido

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"

	"log"
	"math/big"
)

type ECDSASignature struct {
	R, S *big.Int
}

func (k6fido *K6Fido) GenerateKeyPair() (string, string) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	// Marshal the private key into DER format
	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}

	derPublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	// Return the Base64 encoding of the DER keys
	return base64.StdEncoding.EncodeToString(derPrivateKey), base64.StdEncoding.EncodeToString(derPublicKey)
}

// SignData signs the data using the ECDSA private key and SHA256 hashing algorithm
func (k6fido *K6Fido) SignData(signatureData string, base64PrivateKey string) (string, error) {
	signatureDataBytes := []byte(signatureData)
	signedData, err := SignDataLocal(signatureDataBytes, base64PrivateKey)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signedData), nil
}

// SignData signs the data using the ECDSA private key and SHA256 hashing algorithm
func SignDataLocal(signatureData []byte, base64PrivateKey string) ([]byte, error) {
	derPrivateKey, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		log.Fatalf("Failed to decode base64 private key: %v", err)
	}

	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(derPrivateKey)
	if err != nil {
		log.Fatalf("Failed to parse PKCS8 private key: %v", err)
	}
	privateKey, ok := privateKeyInterface.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatalf("Could not assert privateKeyInterface to an *ecdsa.PrivateKey")
	}

	// Hash the data
	h := sha256.New()
	h.Write(signatureData)
	hash := h.Sum(nil)

	// Sign the hash using the private key
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		log.Fatalf("failed to sign data: %v", err)
	}

	// Create an ECDSASignature instance
	ecdsaSig := ECDSASignature{r, s}

	// Marshal the signature into ASN.1 DER form
	signature, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		log.Fatalf("failed to ASN.1 DER marshal ECDSA signature: %v", err)
	}

	return signature, nil
}
