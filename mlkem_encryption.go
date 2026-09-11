// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// CipherAlgorithmSecurosysMLKEMAES256GCM identifies the Securosys-specific
// hybrid encryption construction. It is not a standardized ML-KEM encryption
// algorithm.
const CipherAlgorithmSecurosysMLKEMAES256GCM CipherAlgorithm = "SECUROSYS_MLKEM_AES_256_GCM"

const (
	mlKEMEnvelopeMagic   = "SHSMMLKEM"
	mlKEMEnvelopeVersion = byte(1)
	mlKEMHKDFInfo        = "securosys/ml-kem/aes-256-gcm/v1"
	mlKEMNonceSize       = 12

	mlKEMVersionOffset          = len(mlKEMEnvelopeMagic)
	mlKEMCiphertextLengthOffset = mlKEMVersionOffset + 1
	mlKEMHeaderSize             = mlKEMCiphertextLengthOffset + 4
)

// EncryptMLKEMHybrid encrypts plaintext using the Securosys hybrid
// construction based on ML-KEM, HKDF-SHA-256, and AES-256-GCM.
// The returned ciphertext uses the versioned Securosys SHSMMLKEM envelope
// format. This is not a standardized ML-KEM encryption scheme.
func (c *TSBClient) EncryptMLKEMHybrid(ctx context.Context, label, password string, plaintext, aad []byte) ([]byte, error) {
	key, err := c.GetKey(ctx, label, password)
	if err != nil {
		return nil, fmt.Errorf("get ML-KEM key: %w", err)
	}
	if key.PublicKey == "" {
		return nil, errors.New("ML-KEM key does not have a public key")
	}

	encapsulation, _, err := c.Encapsulate(ctx, key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulation failed: %w", err)
	}
	if encapsulation == nil || encapsulation.Ciphertext == "" || encapsulation.SharedSecret == "" {
		return nil, errors.New("ML-KEM encapsulation returned an incomplete response")
	}

	aead, err := mlKEMAEAD(encapsulation.SharedSecret, encapsulation.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulation returned an invalid shared secret: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate ML-KEM payload nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, aad)

	return marshalMLKEMEnvelope(encapsulation.Ciphertext, nonce, sealed)
}

// DecryptMLKEMHybrid decrypts a ciphertext produced by EncryptMLKEMHybrid.
// Decapsulate transparently waits for approvals when the key has a policy.
func (c *TSBClient) DecryptMLKEMHybrid(ctx context.Context, label, password string, ciphertext, aad []byte) ([]byte, error) {
	kemCiphertext, nonce, sealed, err := unmarshalMLKEMEnvelope(ciphertext)
	if err != nil {
		return nil, err
	}

	decapsulation, _, err := c.Decapsulate(ctx, label, password, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}
	if decapsulation == nil || decapsulation.SharedSecret == "" {
		return nil, errors.New("ML-KEM decapsulation returned an empty shared secret")
	}

	aead, err := mlKEMAEAD(decapsulation.SharedSecret, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation returned an invalid shared secret: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM payload authentication failed: %w", err)
	}
	return plaintext, nil
}

func mlKEMAEAD(encodedSecret, kemCiphertext string) (cipher.AEAD, error) {
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("shared secret is empty")
	}
	defer clear(secret)

	key, err := hkdf.Key(sha256.New, secret, []byte(kemCiphertext), mlKEMHKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func marshalMLKEMEnvelope(kemCiphertext string, nonce, sealed []byte) ([]byte, error) {
	if kemCiphertext == "" {
		return nil, errors.New("ML-KEM ciphertext is empty")
	}
	if len(nonce) != mlKEMNonceSize {
		return nil, fmt.Errorf("invalid ML-KEM payload nonce length: %d", len(nonce))
	}

	envelope := make([]byte, 0, mlKEMHeaderSize+len(kemCiphertext)+len(nonce)+len(sealed))
	envelope = append(envelope, mlKEMEnvelopeMagic...)
	envelope = append(envelope, mlKEMEnvelopeVersion)
	envelope = binary.BigEndian.AppendUint32(envelope, uint32(len(kemCiphertext)))
	envelope = append(envelope, kemCiphertext...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, sealed...)
	return envelope, nil
}

func unmarshalMLKEMEnvelope(envelope []byte) (string, []byte, []byte, error) {
	if len(envelope) < mlKEMHeaderSize || !bytes.HasPrefix(envelope, []byte(mlKEMEnvelopeMagic)) {
		return "", nil, nil, errors.New("invalid ML-KEM ciphertext envelope")
	}
	if envelope[mlKEMVersionOffset] != mlKEMEnvelopeVersion {
		return "", nil, nil, fmt.Errorf("unsupported ML-KEM ciphertext envelope version: %d", envelope[mlKEMVersionOffset])
	}

	kemLength := int(binary.BigEndian.Uint32(envelope[mlKEMCiphertextLengthOffset:]))
	if kemLength == 0 {
		return "", nil, nil, errors.New("invalid ML-KEM ciphertext length")
	}
	sealedOffset := mlKEMHeaderSize + kemLength + mlKEMNonceSize
	if sealedOffset > len(envelope) || len(envelope)-sealedOffset < aes.BlockSize {
		return "", nil, nil, errors.New("truncated ML-KEM ciphertext envelope")
	}

	kemCiphertext := string(envelope[mlKEMHeaderSize : mlKEMHeaderSize+kemLength])
	nonce := bytes.Clone(envelope[sealedOffset-mlKEMNonceSize : sealedOffset])
	sealed := bytes.Clone(envelope[sealedOffset:])
	return kemCiphertext, nonce, sealed, nil
}
