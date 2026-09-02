// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net/http"
	"testing"
)

func TestEncapsulateAndDecapsulateWithTSB(t *testing.T) {
	tsbClient := newTestTSBClientFromEnv(t)

	for _, keyType := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} {
		keyType := keyType
		t.Run(keyType, func(t *testing.T) {
			label := "go-client-test-encapsulation-" + safeTestKeyLabel(keyType)
			createMLKEMTestKey(t, tsbClient, label, keyType)
			defer deleteTestKeyIfExists(t, tsbClient, label)

			key, err := tsbClient.GetKey(context.Background(), label, testKeyPassword)
			requireNoError(t, err)
			if key.PublicKey == "" {
				t.Fatal("TSB returned an empty ML-KEM public key")
			}

			encapsulation, code, err := tsbClient.Encapsulate(context.Background(), key.PublicKey)
			requireNoError(t, err)
			if code != http.StatusOK {
				t.Fatalf("encapsulate status = %d, want %d", code, http.StatusOK)
			}
			if encapsulation.SharedSecret == "" || encapsulation.Ciphertext == "" {
				t.Fatalf("encapsulate returned an incomplete response: %+v", encapsulation)
			}

			decapsulation, code, err := tsbClient.Decapsulate(context.Background(), label, testKeyPassword, encapsulation.Ciphertext)
			requireNoError(t, err)
			if code != http.StatusOK {
				t.Fatalf("synchronous decapsulate status = %d, want %d", code, http.StatusOK)
			}
			if decapsulation.SharedSecret != encapsulation.SharedSecret {
				t.Fatal("decapsulated shared secret does not match the encapsulated shared secret")
			}
		})
	}
}

func TestAsyncDecapsulateWithTSB(t *testing.T) {
	tsbClient := newTestTSBClientFromEnv(t)
	label := "go-client-test-async-decapsulation-ml_kem_512"
	createMLKEMTestKey(t, tsbClient, label, "ML-KEM-512")
	defer deleteTestKeyIfExists(t, tsbClient, label)

	key, err := tsbClient.GetKey(context.Background(), label, testKeyPassword)
	requireNoError(t, err)
	encapsulation, _, err := tsbClient.Encapsulate(context.Background(), key.PublicKey)
	requireNoError(t, err)

	requestID, code, err := tsbClient.AsyncDecapsulate(
		context.Background(),
		label,
		testKeyPassword,
		encapsulation.Ciphertext,
		map[string]string{"purpose": "go-client integration test"},
	)
	requireNoError(t, err)
	if code != http.StatusCreated {
		t.Fatalf("asynchronous decapsulate status = %d, want %d", code, http.StatusCreated)
	}
	if requestID == "" {
		t.Fatal("TSB returned an empty decapsulation request id")
	}
	defer tsbClient.RemoveRequest(context.Background(), requestID)

	request, _, err := tsbClient.GetRequest(context.Background(), requestID)
	requireNoError(t, err)
	if request.Id != requestID {
		t.Fatalf("request id = %q, want %q", request.Id, requestID)
	}
}

func createMLKEMTestKey(t *testing.T, tsbClient *TSBClient, label string, keyType string) {
	t.Helper()
	deleteTestKeyIfExists(t, tsbClient, label)
	createdLabel, err := tsbClient.CreateOrUpdateKey(
		context.Background(),
		label,
		testKeyPassword,
		testPostQuantumWrapKeyAttributes(),
		keyType,
		defaultEmptyKeySize,
		nil,
		"",
		false,
	)
	requireNoError(t, err)
	if createdLabel != label {
		t.Fatalf("created key label = %q, want %q", createdLabel, label)
	}
}
