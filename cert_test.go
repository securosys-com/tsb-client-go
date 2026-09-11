// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCreateMLDSACertificatesWithTSBSignGo127(t *testing.T) {
	tsbClient := newTestTSBClientFromEnv(t)

	for _, keyType := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		keyType := keyType
		t.Run(keyType, func(t *testing.T) {
			label := "go-client-test-go127-cert-" + safeTestKeyLabel(keyType)
			deleteTestKeyIfExists(t, tsbClient, label)
			defer deleteTestKeyIfExists(t, tsbClient, label)

			createdLabel, err := tsbClient.CreateOrUpdateKey(
				context.Background(),
				label,
				testKeyPassword,
				testPostQuantumSignKeyAttributes(),
				keyType,
				defaultEmptyKeySize,
				nil,
				"",
				false,
			)
			requireNoError(t, err)

			publicKey := testMLDSAPublicKey(t, tsbClient, createdLabel, keyType)

			signer := &tsbMLDSASigner{
				client:    tsbClient,
				label:     createdLabel,
				password:  testKeyPassword,
				publicKey: publicKey,
			}
			template := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject: pkix.Name{
					CommonName: label,
				},
				NotBefore:             time.Now().Add(-time.Minute),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
			}

			certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
			requireNoError(t, err)

			cert, err := x509.ParseCertificate(certDER)
			requireNoError(t, err)
			if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
				t.Fatal("x509 parsed ML-DSA certificate with unknown signature algorithm")
			}
			if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
				t.Fatal("x509 parsed ML-DSA certificate with unknown public key algorithm")
			}
			if !strings.Contains(reflect.TypeOf(cert.PublicKey).String(), "mldsa") {
				t.Fatalf("public key type = %T, want crypto/mldsa public key", cert.PublicKey)
			}
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				t.Fatalf("self-signed certificate signature check failed: %v", err)
			}
		})
	}
}

type tsbMLDSASigner struct {
	client    *TSBClient
	label     string
	password  string
	publicKey *mldsa.PublicKey
}

func (s *tsbMLDSASigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *tsbMLDSASigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("unsupported ML-DSA signer hash %v", opts.HashFunc())
	}

	signatureResponse, _, err := s.client.Sign(
		context.Background(),
		s.label,
		s.password,
		base64.StdEncoding.EncodeToString(message),
		testRSASignPayloadType,
		SignatureAlgorithm("ML_DSA"),
		SignatureTypeDER,
	)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(signatureResponse.Signature)
}

func testMLDSAPublicKey(t *testing.T, tsbClient *TSBClient, label string, keyType string) *mldsa.PublicKey {
	t.Helper()

	key, err := tsbClient.GetKey(context.Background(), label, testKeyPassword)
	requireNoError(t, err)

	publicKeyBytes, err := publicKeyDER(key.PublicKey)
	requireNoError(t, err)

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err == nil {
		if mldsaPublicKey, ok := publicKey.(*mldsa.PublicKey); ok {
			return mldsaPublicKey
		}
		t.Fatalf("public key type = %T, want *mldsa.PublicKey", publicKey)
	}

	rawPublicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key.PublicKey))
	requireNoError(t, err)
	mldsaPublicKey, err := mldsa.NewPublicKey(testMLDSAParameters(keyType), rawPublicKey)
	requireNoError(t, err)
	return mldsaPublicKey
}

func publicKeyDER(publicKey string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(publicKey)); block != nil {
		return block.Bytes, nil
	}
	if block, _ := pem.Decode([]byte("-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----\n")); block != nil {
		return block.Bytes, nil
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
}

func testMLDSAParameters(keyType string) mldsa.Parameters {
	switch keyType {
	case "ML-DSA-44":
		return mldsa.MLDSA44()
	case "ML-DSA-65":
		return mldsa.MLDSA65()
	case "ML-DSA-87":
		return mldsa.MLDSA87()
	default:
		panic("unsupported ML-DSA key type: " + keyType)
	}
}
