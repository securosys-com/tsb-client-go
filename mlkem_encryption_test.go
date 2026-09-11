// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestMLKEMEnvelopeRoundTrip(t *testing.T) {
	kemCiphertext := base64.StdEncoding.EncodeToString([]byte("kem ciphertext"))
	nonce := bytes.Repeat([]byte{1}, mlKEMNonceSize)
	sealed := bytes.Repeat([]byte{2}, 32)

	envelope, err := marshalMLKEMEnvelope(kemCiphertext, nonce, sealed)
	if err != nil {
		t.Fatal(err)
	}
	gotCiphertext, gotNonce, gotSealed, err := unmarshalMLKEMEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if gotCiphertext != kemCiphertext || !bytes.Equal(gotNonce, nonce) || !bytes.Equal(gotSealed, sealed) {
		t.Fatal("ML-KEM envelope did not round-trip")
	}
}

func TestMLKEMAEADRoundTrip(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	kemCiphertext := base64.StdEncoding.EncodeToString([]byte("kem ciphertext"))
	plaintext := []byte("plaintext")
	aad := []byte("aad")

	sealer, err := mlKEMAEAD(secret, kemCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{4}, sealer.NonceSize())
	sealed := sealer.Seal(nil, nonce, plaintext, aad)

	opener, err := mlKEMAEAD(secret, kemCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := opener.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
}
