// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

const (
	testRSASignPayload     = "Z28tY2xpZW50LXRlc3QtcGF5bG9hZA=="
	testRSASignPayloadType = "UNSPECIFIED"
	testECSignKeyLabel     = "go-client-test-ec-sign"
	testEDSignKeyLabel     = "go-client-test-ed-sign"
	testRSASignKeyLabel    = "go-client-test-rsa-sign"
	testDSASignKeyLabel    = "go-client-test-dsa-sign"
	testBLSSignKeyLabel    = "go-client-test-bls-sign"
)

type testSignCase struct {
	keyType             string
	label               string
	keySize             float64
	curveOID            string
	signatureType       SignatureType
	signatureAlgorithms []SignatureAlgorithm
}

func TestCreateSignVerifyAllAlgorithmsAndDeleteKeyWithTSB(t *testing.T) {
	tsbClient := newTestTSBClientFromEnv(t)

	for _, tc := range testSignCases() {
		t.Run(tc.keyType, func(t *testing.T) {
			deleteTestKeyIfExists(t, tsbClient, tc.label)
			defer deleteTestKeyIfExists(t, tsbClient, tc.label)

			label, err := tsbClient.CreateOrUpdateKey(
				tc.label,
				testKeyPassword,
				testKeyAttributes(),
				tc.keyType,
				tc.keySize,
				nil,
				tc.curveOID,
				false,
			)
			requireNoError(t, err)

			for _, signatureAlgorithm := range tc.signatureAlgorithms {
				t.Run(string(signatureAlgorithm), func(t *testing.T) {
					payload := testPayloadForSignatureAlgorithm(t, signatureAlgorithm)
					signatureResponse, statusCode, err := tsbClient.Sign(
						context.Background(),
						label,
						testKeyPassword,
						payload,
						testRSASignPayloadType,
						signatureAlgorithm,
						tc.signatureType,
					)
					requireNoError(t, err)
					if statusCode != http.StatusOK {
						t.Fatalf("sign status code = %d, want %d", statusCode, http.StatusOK)
					}
					if signatureResponse.Signature == "" {
						t.Fatal("signature is empty")
					}

					valid, statusCode, err := tsbClient.Verify(
						context.Background(),
						label,
						testKeyPassword,
						payload,
						signatureAlgorithm,
						signatureResponse.Signature,
					)
					requireNoError(t, err)
					if statusCode != http.StatusOK {
						t.Fatalf("verify status code = %d, want %d", statusCode, http.StatusOK)
					}
					if !valid {
						t.Fatal("signature is not valid")
					}
				})
			}
		})
	}
}

func testPayloadForSignatureAlgorithm(t *testing.T, signatureAlgorithm SignatureAlgorithm) string {
	t.Helper()

	payload, err := base64.StdEncoding.DecodeString(testRSASignPayload)
	requireNoError(t, err)

	switch signatureAlgorithm {
	case SignatureAlgorithmNoneSHA1WithRSA:
		digest := sha1.Sum(payload)
		return base64.StdEncoding.EncodeToString(digest[:])
	case SignatureAlgorithmNoneSHA224WithRSA, SignatureAlgorithmNoneSHA224WithRSAPSS:
		digest := sha256.Sum224(payload)
		return base64.StdEncoding.EncodeToString(digest[:])
	case SignatureAlgorithmNoneSHA256WithRSA, SignatureAlgorithmNoneSHA256WithRSAPSS:
		digest := sha256.Sum256(payload)
		return base64.StdEncoding.EncodeToString(digest[:])
	case SignatureAlgorithmNoneSHA384WithRSA, SignatureAlgorithmNoneSHA384WithRSAPSS:
		digest := sha512.Sum384(payload)
		return base64.StdEncoding.EncodeToString(digest[:])
	case SignatureAlgorithmNoneSHA512WithRSA, SignatureAlgorithmNoneSHA512WithRSAPSS:
		digest := sha512.Sum512(payload)
		return base64.StdEncoding.EncodeToString(digest[:])
	}

	if !strings.HasPrefix(string(signatureAlgorithm), "NONE_WITH_") {
		return testRSASignPayload
	}

	digest := sha256.Sum256(payload)
	return base64.StdEncoding.EncodeToString(digest[:])
}

func testSignCases() []testSignCase {
	return []testSignCase{
		{
			keyType:             keyTypeEC,
			label:               testECSignKeyLabel,
			keySize:             defaultEmptyKeySize,
			curveOID:            testKeyCurveOIDP256,
			signatureType:       SignatureTypeRAW,
			signatureAlgorithms: EC_SIGNATURE_ALGORITHM,
		},
		{
			keyType:             keyTypeED,
			label:               testEDSignKeyLabel,
			keySize:             defaultEmptyKeySize,
			curveOID:            testKeyCurveED,
			signatureType:       SignatureTypeRAW,
			signatureAlgorithms: ED_SIGNATURE_ALGORITHM,
		},
		{
			keyType:             keyTypeRSA,
			label:               testRSASignKeyLabel,
			keySize:             defaultRSAKeySize,
			signatureType:       SignatureTypeDER,
			signatureAlgorithms: RSA_SIGNATURE_ALGORITHM,
		},
		{
			keyType:             keyTypeDSA,
			label:               testDSASignKeyLabel,
			keySize:             defaultDSAKeySize,
			signatureType:       SignatureTypeDER,
			signatureAlgorithms: DSA_SIGNATURE_ALGORITHM,
		},
		{
			keyType:             keyTypeBLS,
			label:               testBLSSignKeyLabel,
			keySize:             defaultEmptyKeySize,
			signatureType:       SignatureTypeDER,
			signatureAlgorithms: BLS_SIGNATURE_ALGORITHM,
		},
	}
}

func TestNormalizeSignatureType(t *testing.T) {
	tests := []struct {
		name      string
		input     SignatureType
		expected  SignatureType
		wantError bool
	}{
		{name: "default", input: "", expected: SignatureTypeDER},
		{name: "der", input: SignatureTypeDER, expected: SignatureTypeDER},
		{name: "eth", input: SignatureTypeETH, expected: SignatureTypeETH},
		{name: "raw", input: SignatureTypeRAW, expected: SignatureTypeRAW},
		{name: "invalid", input: SignatureType("INVALID"), wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeSignatureType(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			requireNoError(t, err)
			if got != tt.expected {
				t.Fatalf("signature type = %q, want %q", got, tt.expected)
			}
		})
	}
}
