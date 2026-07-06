// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

const (
	testEncryptPayload       = "MDEyMzQ1Njc4OWFiY2RlZg=="
	testEncryptAAD           = ""
	testRSAEncryptKeyLabel   = "go-client-test-rsa-encrypt"
	testAESEncryptKeyLabel   = "go-client-test-aes-encrypt"
	testChaCha20EncryptLabel = "go-client-test-chacha20-encrypt"
	testCamelliaEncryptLabel = "go-client-test-camellia-encrypt"
	testTDEAEncryptKeyLabel  = "go-client-test-tdea-encrypt"
	defaultEncryptTagLength  = -1
	defaultAESGCMTagLength   = 128
	expectedDecryptStatus    = http.StatusOK
	expectedEncryptStatus    = http.StatusOK
)

type testEncryptDecryptCase struct {
	keyType          string
	label            string
	keySize          float64
	cipherAlgorithms []CipherAlgorithm
	attributes       map[string]bool
}

func TestCreateEncryptDecryptAndDeleteKeysWithTSB(t *testing.T) {
	tsbClient := newTestTSBClientFromEnv(t)

	for _, tc := range testEncryptDecryptCases() {
		t.Run(tc.keyType, func(t *testing.T) {
			deleteTestKeyIfExists(t, tsbClient, tc.label)
			defer deleteTestKeyIfExists(t, tsbClient, tc.label)

			label, err := tsbClient.CreateOrUpdateKey(
				tc.label,
				testKeyPassword,
				tc.attributes,
				tc.keyType,
				tc.keySize,
				nil,
				"",
				false,
			)
			requireNoError(t, err)

			for _, cipherAlgorithm := range tc.cipherAlgorithms {
				t.Run(string(cipherAlgorithm), func(t *testing.T) {
					tagLength := testTagLengthForCipherAlgorithm(cipherAlgorithm)
					encryptResponse, statusCode, err := tsbClient.Encrypt(
						context.Background(),
						label,
						testKeyPassword,
						testEncryptPayload,
						cipherAlgorithm,
						tagLength,
						testEncryptAAD,
					)
					requireNoError(t, err)
					if statusCode != expectedEncryptStatus {
						t.Fatalf("encrypt status code = %d, want %d", statusCode, expectedEncryptStatus)
					}
					if encryptResponse.EncryptedPayload == "" {
						t.Fatal("encrypted payload is empty")
					}

					vector := ""
					if encryptResponse.InitializationVector != nil {
						vector = *encryptResponse.InitializationVector
					}

					decryptResponse, statusCode, err := tsbClient.Decrypt(
						context.Background(),
						label,
						testKeyPassword,
						encryptResponse.EncryptedPayload,
						vector,
						cipherAlgorithm,
						tagLength,
						testEncryptAAD,
					)
					requireNoError(t, err)
					if statusCode != expectedDecryptStatus {
						t.Fatalf("decrypt status code = %d, want %d", statusCode, expectedDecryptStatus)
					}
					expectedPayload := testDecryptPayloadForCipherAlgorithm(t, cipherAlgorithm, tc.keySize)
					if decryptResponse.Payload != expectedPayload {
						t.Fatalf("decrypted payload = %q, want %q", decryptResponse.Payload, expectedPayload)
					}
				})
			}
		})
	}
}

func testTagLengthForCipherAlgorithm(cipherAlgorithm CipherAlgorithm) int {
	if cipherAlgorithm == CipherAlgorithmAESGCM {
		return defaultAESGCMTagLength
	}
	return defaultEncryptTagLength
}

func testDecryptPayloadForCipherAlgorithm(t *testing.T, cipherAlgorithm CipherAlgorithm, keySize float64) string {
	t.Helper()

	if cipherAlgorithm != CipherAlgorithmRSANoPadding {
		return testEncryptPayload
	}

	payload, err := base64.StdEncoding.DecodeString(testEncryptPayload)
	requireNoError(t, err)

	keySizeBytes := int(keySize) / 8
	if len(payload) > keySizeBytes {
		t.Fatalf("test payload length = %d bytes, want at most %d bytes", len(payload), keySizeBytes)
	}

	paddedPayload := make([]byte, keySizeBytes)
	copy(paddedPayload[keySizeBytes-len(payload):], payload)
	return base64.StdEncoding.EncodeToString(paddedPayload)
}

func testEncryptDecryptCases() []testEncryptDecryptCase {
	return []testEncryptDecryptCase{
		{
			keyType:          keyTypeRSA,
			label:            testRSAEncryptKeyLabel,
			keySize:          defaultRSAKeySize,
			cipherAlgorithms: RSA_CIPHER_ALGORITHM,
			attributes:       testKeyAttributes(),
		},
		{
			keyType:          keyTypeAES,
			label:            testAESEncryptKeyLabel,
			keySize:          defaultAESKeySize,
			cipherAlgorithms: AES_CIPHER_ALGORITHM,
			attributes:       testKeyAttributes(),
		},
		{
			keyType:          keyTypeChaCha20,
			label:            testChaCha20EncryptLabel,
			keySize:          defaultChaCha20Size,
			cipherAlgorithms: CHACHA20_CIPHER_ALGORITHM,
			attributes:       testKeyAttributes(),
		},
		{
			keyType:          keyTypeCamellia,
			label:            testCamelliaEncryptLabel,
			keySize:          defaultCamelliaSize,
			cipherAlgorithms: CAMELLIA_CIPHER_ALGORITHM,
			attributes:       testKeyAttributes(),
		},
		{
			keyType:          keyTypeTDEA,
			label:            testTDEAEncryptKeyLabel,
			keySize:          defaultTDEAKeySize,
			cipherAlgorithms: TDEA_CIPHER_ALGORITHM,
			attributes:       testKeyAttributes(),
		},
	}
}

func TestEncryptDecryptTestCasesUseSupportedTypes(t *testing.T) {
	supported := make(map[string]struct{}, len(helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS))
	for _, keyType := range helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS {
		supported[strings.ToUpper(keyType)] = struct{}{}
	}
	for _, tc := range testEncryptDecryptCases() {
		if _, ok := supported[strings.ToUpper(tc.keyType)]; !ok {
			t.Fatalf("test key type %q is not listed in helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS", tc.keyType)
		}
	}
}
