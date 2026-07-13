// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

const (
	testWrapKeyLabelPrefix      = "go-client-test-wrap-key"
	testWrappedKeyLabelPrefix   = "go-client-test-wrap-src"
	testUnwrappedKeyLabelPrefix = "go-client-test-wrap-dst"
	expectedWrapStatus          = http.StatusOK
	expectedUnwrapStatus        = http.StatusCreated
)

type testWrapUnwrapCase struct {
	name            string
	wrapKeyType     string
	wrapKeySize     float64
	wrapMethod      WrapMethod
	wrappedKeyType  string
	wrappedKeySize  float64
	wrappedCurveOID string
}

func TestCreateWrapUnwrapAndDeleteKeysWithTSB(t *testing.T) {
	tsbClient := newTestTSBClientFromEnv(t)

	for i, tc := range testWrapUnwrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			wrapKeyLabel := fmt.Sprintf("%s-%02d", testWrapKeyLabelPrefix, i)
			wrappedKeyLabel := fmt.Sprintf("%s-%02d", testWrappedKeyLabelPrefix, i)
			unwrappedKeyLabel := fmt.Sprintf("%s-%02d", testUnwrappedKeyLabelPrefix, i)

			deleteTestKeyIfExists(t, tsbClient, wrapKeyLabel)
			deleteTestKeyIfExists(t, tsbClient, wrappedKeyLabel)
			deleteTestKeyIfExists(t, tsbClient, unwrappedKeyLabel)
			defer deleteTestKeyIfExists(t, tsbClient, wrapKeyLabel)
			defer deleteTestKeyIfExists(t, tsbClient, wrappedKeyLabel)
			defer deleteTestKeyIfExists(t, tsbClient, unwrappedKeyLabel)

			createdWrapKeyLabel, err := tsbClient.CreateOrUpdateKey(
				context.Background(),
				wrapKeyLabel,
				testKeyPassword,
				testKeyAttributes(),
				tc.wrapKeyType,
				tc.wrapKeySize,
				nil,
				"",
				false,
			)
			requireNoError(t, err)

			createdWrappedKeyLabel, err := tsbClient.CreateOrUpdateKey(
				context.Background(),
				wrappedKeyLabel,
				testKeyPassword,
				testKeyAttributes(),
				tc.wrappedKeyType,
				tc.wrappedKeySize,
				nil,
				tc.wrappedCurveOID,
				false,
			)
			requireNoError(t, err)

			wrapResponse, statusCode, err := tsbClient.Wrap(
				createdWrapKeyLabel,
				testKeyPassword,
				createdWrappedKeyLabel,
				testKeyPassword,
				tc.wrapMethod,
			)
			requireNoError(t, err)
			if statusCode != expectedWrapStatus {
				t.Fatalf("wrap status code = %d, want %d", statusCode, expectedWrapStatus)
			}
			if wrapResponse.WrappedKey == "" {
				t.Fatal("wrapped key is empty")
			}

			statusCode, err = tsbClient.UnWrap(
				wrapResponse.WrappedKey,
				unwrappedKeyLabel,
				testKeyAttributes(),
				createdWrapKeyLabel,
				testKeyPassword,
				tc.wrapMethod,
				nil,
			)
			requireNoError(t, err)
			if statusCode != expectedUnwrapStatus {
				t.Fatalf("unwrap status code = %d, want %d", statusCode, expectedUnwrapStatus)
			}

			unwrappedKey, err := tsbClient.GetKey(context.Background(), unwrappedKeyLabel, testKeyPassword)
			requireNoError(t, err)
			if unwrappedKey.Algorithm != tc.wrappedKeyType {
				t.Fatalf("unwrapped key algorithm = %q, want %q", unwrappedKey.Algorithm, tc.wrappedKeyType)
			}
		})
	}
}

func TestCreatePostQuantumWrapUnwrapAndDeleteKeysWithTSB(t *testing.T) {
	t.Skip("current TSB /v1/wrap endpoint does not accept ML-KEM wrapMethod values; PQC key creation is covered by TestCreateAndDeletePostQuantumKeysWithTSB")

	tsbClient := newTestTSBClientFromEnv(t)

	for i, tc := range testPostQuantumWrapUnwrapCases() {
		i := i
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			wrapKeyLabel := fmt.Sprintf("%s-pqc-%02d", testWrapKeyLabelPrefix, i)
			wrappedKeyLabel := fmt.Sprintf("%s-pqc-%02d", testWrappedKeyLabelPrefix, i)
			unwrappedKeyLabel := fmt.Sprintf("%s-pqc-%02d", testUnwrappedKeyLabelPrefix, i)

			deleteTestKeyIfExists(t, tsbClient, wrapKeyLabel)
			deleteTestKeyIfExists(t, tsbClient, wrappedKeyLabel)
			deleteTestKeyIfExists(t, tsbClient, unwrappedKeyLabel)
			defer deleteTestKeyIfExists(t, tsbClient, wrapKeyLabel)
			defer deleteTestKeyIfExists(t, tsbClient, wrappedKeyLabel)
			defer deleteTestKeyIfExists(t, tsbClient, unwrappedKeyLabel)

			createdWrapKeyLabel, err := tsbClient.CreateOrUpdateKey(
				context.Background(),
				wrapKeyLabel,
				testKeyPassword,
				testPostQuantumWrapKeyAttributes(),
				tc.wrapKeyType,
				tc.wrapKeySize,
				nil,
				"",
				false,
			)
			requireNoError(t, err)

			createdWrappedKeyLabel, err := tsbClient.CreateOrUpdateKey(
				context.Background(),
				wrappedKeyLabel,
				testKeyPassword,
				testKeyAttributes(),
				tc.wrappedKeyType,
				tc.wrappedKeySize,
				nil,
				tc.wrappedCurveOID,
				false,
			)
			requireNoError(t, err)

			wrapResponse, statusCode, err := tsbClient.Wrap(
				createdWrapKeyLabel,
				testKeyPassword,
				createdWrappedKeyLabel,
				testKeyPassword,
				tc.wrapMethod,
			)
			requireNoError(t, err)
			if statusCode != expectedWrapStatus {
				t.Fatalf("wrap status code = %d, want %d", statusCode, expectedWrapStatus)
			}
			if wrapResponse.WrappedKey == "" {
				t.Fatal("wrapped key is empty")
			}

			statusCode, err = tsbClient.UnWrap(
				wrapResponse.WrappedKey,
				unwrappedKeyLabel,
				testKeyAttributes(),
				createdWrapKeyLabel,
				testKeyPassword,
				tc.wrapMethod,
				nil,
			)
			requireNoError(t, err)
			if statusCode != expectedUnwrapStatus {
				t.Fatalf("unwrap status code = %d, want %d", statusCode, expectedUnwrapStatus)
			}

			unwrappedKey, err := tsbClient.GetKey(context.Background(), unwrappedKeyLabel, testKeyPassword)
			requireNoError(t, err)
			if unwrappedKey.Algorithm != tc.wrappedKeyType {
				t.Fatalf("unwrapped key algorithm = %q, want %q", unwrappedKey.Algorithm, tc.wrappedKeyType)
			}
		})
	}
}

func testWrapUnwrapCases() []testWrapUnwrapCase {
	return []testWrapUnwrapCase{
		{
			name:           string(WrapMethodAES),
			wrapKeyType:    keyTypeAES,
			wrapKeySize:    defaultAESKeySize,
			wrapMethod:     WrapMethodAES,
			wrappedKeyType: keyTypeAES,
			wrappedKeySize: defaultAESKeySize,
		},
		{
			name:           string(WrapMethodAESDSA),
			wrapKeyType:    keyTypeAES,
			wrapKeySize:    defaultAESKeySize,
			wrapMethod:     WrapMethodAESDSA,
			wrappedKeyType: keyTypeDSA,
			wrappedKeySize: defaultDSAKeySize,
		},
		{
			name:            string(WrapMethodAESEC),
			wrapKeyType:     keyTypeAES,
			wrapKeySize:     defaultAESKeySize,
			wrapMethod:      WrapMethodAESEC,
			wrappedKeyType:  keyTypeEC,
			wrappedKeySize:  defaultEmptyKeySize,
			wrappedCurveOID: testKeyCurveOIDP256,
		},
		{
			name:            string(WrapMethodAESED),
			wrapKeyType:     keyTypeAES,
			wrapKeySize:     defaultAESKeySize,
			wrapMethod:      WrapMethodAESED,
			wrappedKeyType:  keyTypeED,
			wrappedKeySize:  defaultEmptyKeySize,
			wrappedCurveOID: testKeyCurveED,
		},
		{
			name:           string(WrapMethodAESRSA),
			wrapKeyType:    keyTypeAES,
			wrapKeySize:    defaultAESKeySize,
			wrapMethod:     WrapMethodAESRSA,
			wrappedKeyType: keyTypeRSA,
			wrappedKeySize: defaultRSAKeySize,
		},
		{
			name:           string(WrapMethodAESBLS),
			wrapKeyType:    keyTypeAES,
			wrapKeySize:    defaultAESKeySize,
			wrapMethod:     WrapMethodAESBLS,
			wrappedKeyType: keyTypeBLS,
			wrappedKeySize: defaultEmptyKeySize,
		},
		{
			name:           string(WrapMethodAESPad),
			wrapKeyType:    keyTypeAES,
			wrapKeySize:    defaultAESKeySize,
			wrapMethod:     WrapMethodAESPad,
			wrappedKeyType: keyTypeAES,
			wrappedKeySize: defaultAESKeySize,
		},
		{
			name:           string(WrapMethodAESPadDSA),
			wrapKeyType:    keyTypeAES,
			wrapKeySize:    defaultAESKeySize,
			wrapMethod:     WrapMethodAESPadDSA,
			wrappedKeyType: keyTypeDSA,
			wrappedKeySize: defaultDSAKeySize,
		},
		{
			name:            string(WrapMethodAESPadEC),
			wrapKeyType:     keyTypeAES,
			wrapKeySize:     defaultAESKeySize,
			wrapMethod:      WrapMethodAESPadEC,
			wrappedKeyType:  keyTypeEC,
			wrappedKeySize:  defaultEmptyKeySize,
			wrappedCurveOID: testKeyCurveOIDP256,
		},
		{
			name:            string(WrapMethodAESPadED),
			wrapKeyType:     keyTypeAES,
			wrapKeySize:     defaultAESKeySize,
			wrapMethod:      WrapMethodAESPadED,
			wrappedKeyType:  keyTypeED,
			wrappedKeySize:  defaultEmptyKeySize,
			wrappedCurveOID: testKeyCurveED,
		},
		{
			name:           string(WrapMethodAESPadRSA),
			wrapKeyType:    keyTypeAES,
			wrapKeySize:    defaultAESKeySize,
			wrapMethod:     WrapMethodAESPadRSA,
			wrappedKeyType: keyTypeRSA,
			wrappedKeySize: defaultRSAKeySize,
		},
		{
			name:           string(WrapMethodAESPadBLS),
			wrapKeyType:    keyTypeAES,
			wrapKeySize:    defaultAESKeySize,
			wrapMethod:     WrapMethodAESPadBLS,
			wrappedKeyType: keyTypeBLS,
			wrappedKeySize: defaultEmptyKeySize,
		},
		{
			name:           string(WrapMethodRSAPad),
			wrapKeyType:    keyTypeRSA,
			wrapKeySize:    defaultRSAKeySize,
			wrapMethod:     WrapMethodRSAPad,
			wrappedKeyType: keyTypeAES,
			wrappedKeySize: defaultAESKeySize,
		},
		{
			name:           string(WrapMethodRSAOAEP),
			wrapKeyType:    keyTypeRSA,
			wrapKeySize:    defaultRSAKeySize,
			wrapMethod:     WrapMethodRSAOAEP,
			wrappedKeyType: keyTypeAES,
			wrappedKeySize: defaultAESKeySize,
		},
	}
}

func TestPostQuantumWrapKeyTypesAreSupported(t *testing.T) {
	supported := make(map[string]struct{}, len(helpers.SUPPORTED_WRAP_KEYS))
	for _, keyType := range helpers.SUPPORTED_WRAP_KEYS {
		supported[keyType] = struct{}{}
	}
	for _, tc := range testPostQuantumWrapUnwrapCases() {
		if _, ok := supported[tc.wrapKeyType]; !ok {
			t.Fatalf("post-quantum wrap key type %q is not listed in helpers.SUPPORTED_WRAP_KEYS", tc.wrapKeyType)
		}
	}
}

func testPostQuantumWrapUnwrapCases() []testWrapUnwrapCase {
	return []testWrapUnwrapCase{
		{
			name:           string(WrapMethodMLKEM512),
			wrapKeyType:    "ML-KEM-512",
			wrapKeySize:    defaultEmptyKeySize,
			wrapMethod:     WrapMethodMLKEM512,
			wrappedKeyType: keyTypeAES,
			wrappedKeySize: defaultAESKeySize,
		},
		{
			name:           string(WrapMethodMLKEM768),
			wrapKeyType:    "ML-KEM-768",
			wrapKeySize:    defaultEmptyKeySize,
			wrapMethod:     WrapMethodMLKEM768,
			wrappedKeyType: keyTypeAES,
			wrappedKeySize: defaultAESKeySize,
		},
		{
			name:           string(WrapMethodMLKEM1024),
			wrapKeyType:    "ML-KEM-1024",
			wrapKeySize:    defaultEmptyKeySize,
			wrapMethod:     WrapMethodMLKEM1024,
			wrappedKeyType: keyTypeAES,
			wrappedKeySize: defaultAESKeySize,
		},
	}
}

func testPostQuantumWrapKeyAttributes() map[string]bool {
	return map[string]bool{
		attributeDecrypt:     false,
		attributeEncrypt:     false,
		attributeDestroyable: true,
		attributeExtractable: true,
		attributeSign:        false,
		attributeUnwrap:      true,
		attributeVerify:      false,
		attributeWrap:        true,
	}
}
