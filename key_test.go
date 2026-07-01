// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"testing"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

const (
	testKeyPassword      = ""
	testKeyCurveOIDP256  = "1.2.840.10045.3.1.7"
	testKeyCurveED       = "1.3.101.112"
	testECKeyLabel       = "go-client-test-ec"
	testEDKeyLabel       = "go-client-test-ed"
	testRSAKeyLabel      = "go-client-test-rsa"
	testDSAKeyLabel      = "go-client-test-dsa"
	testBLSKeyLabel      = "go-client-test-bls"
	testAESKeyLabel      = "go-client-test-aes"
	testChaCha20KeyLabel = "go-client-test-chacha20"
	testCamelliaKeyLabel = "go-client-test-camellia"
	testTDEAKeyLabel     = "go-client-test-tdea"
	defaultAESKeySize    = 256
	defaultRSAKeySize    = 2048
	defaultDSAKeySize    = 2048
	defaultCamelliaSize  = 256
	defaultChaCha20Size  = 256
	defaultTDEAKeySize   = 0
	defaultEmptyKeySize  = 0
	keyTypeEC            = "EC"
	keyTypeED            = "ED"
	keyTypeRSA           = "RSA"
	keyTypeDSA           = "DSA"
	keyTypeBLS           = "BLS"
	keyTypeAES           = "AES"
	keyTypeChaCha20      = "ChaCha20"
	keyTypeCamellia      = "Camellia"
	keyTypeTDEA          = "TDEA"
	attributeDecrypt     = "decrypt"
	attributeEncrypt     = "encrypt"
	attributeExtractable = "extractable"
	attributeSign        = "sign"
	attributeUnwrap      = "unwrap"
	attributeVerify      = "verify"
	attributeWrap        = "wrap"
	attributeDestroyable = "destroyable"
)

type testKeyCase struct {
	keyType    string
	label      string
	keySize    float64
	curveOID   string
	attributes map[string]bool
}

func TestCreateAndDeleteKeyWithTSB(t *testing.T) {
	tsbClient := newTestTSBClientFromEnv(t)

	for _, tc := range testKeyCases() {
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
				tc.curveOID,
				false,
			)
			requireNoError(t, err)

			if label != tc.label {
				t.Fatalf("label = %q, want %q", label, tc.label)
			}
		})
	}
}

func deleteTestKeyIfExists(t *testing.T, tsbClient *TSBClient, label string) {
	t.Helper()
	if label == "" {
		return
	}
	tsbClient.RemoveKey(label)
}

func testKeyCases() []testKeyCase {
	return []testKeyCase{
		{
			keyType:    keyTypeEC,
			label:      testECKeyLabel,
			keySize:    defaultEmptyKeySize,
			curveOID:   testKeyCurveOIDP256,
			attributes: testKeyAttributes(),
		},
		{
			keyType:    keyTypeED,
			label:      testEDKeyLabel,
			keySize:    defaultEmptyKeySize,
			curveOID:   testKeyCurveED,
			attributes: testKeyAttributes(),
		},
		{
			keyType:    keyTypeRSA,
			label:      testRSAKeyLabel,
			keySize:    defaultRSAKeySize,
			attributes: testKeyAttributes(),
		},
		{
			keyType:    keyTypeDSA,
			label:      testDSAKeyLabel,
			keySize:    defaultDSAKeySize,
			attributes: testKeyAttributes(),
		},
		{
			keyType:    keyTypeBLS,
			label:      testBLSKeyLabel,
			keySize:    defaultEmptyKeySize,
			attributes: testKeyAttributes(),
		},
		{
			keyType:    keyTypeAES,
			label:      testAESKeyLabel,
			keySize:    defaultAESKeySize,
			attributes: testKeyAttributes(),
		},
		{
			keyType:    keyTypeChaCha20,
			label:      testChaCha20KeyLabel,
			keySize:    defaultChaCha20Size,
			attributes: testKeyAttributes(),
		},
		{
			keyType:    keyTypeCamellia,
			label:      testCamelliaKeyLabel,
			keySize:    defaultCamelliaSize,
			attributes: testKeyAttributes(),
		},
		{
			keyType:    keyTypeTDEA,
			label:      testTDEAKeyLabel,
			keySize:    defaultTDEAKeySize,
			attributes: testKeyAttributes(),
		},
	}
}

func testKeyAttributes() map[string]bool {
	return map[string]bool{
		attributeDecrypt:     true,
		attributeEncrypt:     true,
		attributeExtractable: true,
		attributeSign:        true,
		attributeUnwrap:      true,
		attributeVerify:      true,
		attributeWrap:        true,
		attributeDestroyable: true,
	}
}

func TestKeyTestCasesUseSupportedTypes(t *testing.T) {
	supported := make(map[string]struct{}, len(helpers.SUPPORTED_KEY_TYPES))
	for _, keyType := range helpers.SUPPORTED_KEY_TYPES {
		supported[keyType] = struct{}{}
	}
	for _, tc := range testKeyCases() {
		if _, ok := supported[tc.keyType]; !ok {
			t.Fatalf("test key type %q is not listed in helpers.SUPPORTED_KEY_TYPES", tc.keyType)
		}
	}
}
