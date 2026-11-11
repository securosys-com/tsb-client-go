// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

// injectionValue would break out of the JSON string and add a field if it
// were concatenated into a payload instead of being properly encoded. It
// also contains characters that json.Marshal HTML-escapes by default.
const injectionValue = `evil", "injected": true, "x": "<&>\` + "\n"

type capturedRequest struct {
	path string
	body []byte
}

func newCapturingTSBClient(t *testing.T, withAppKey bool) (*TSBClient, *rsa.PublicKey, *[]capturedRequest) {
	t.Helper()
	var captured []capturedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		captured = append(captured, capturedRequest{path: r.URL.Path, body: body})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"blockKeyRequestId": "id", "unblockKeyRequestId": "id",
			"modifyKeyRequestId": "id", "decryptRequestId": "id",
			"signRequestId": "id", "unwrapRequestId": "id",
			"signatureValid": true
		}`))
	}))
	t.Cleanup(server.Close)

	auth := AuthStruct{AuthType: authTypeNone, AppName: testAppName}
	var publicKey *rsa.PublicKey
	if withAppKey {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		requireNoError(t, err)
		privateKeyB64 := b64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privateKey))
		publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		requireNoError(t, err)
		publicKeyB64 := b64.StdEncoding.EncodeToString(publicKeyDER)
		auth.ApplicationKeyPair = KeyPair{PrivateKey: &privateKeyB64, PublicKey: &publicKeyB64}
		publicKey = &privateKey.PublicKey
	}

	client, err := NewTSBClient(server.URL, auth)
	requireNoError(t, err)
	return client, publicKey, &captured
}

type payloadCase struct {
	name string
	path string
	// wrapper is the key the request object is nested under ("" for none).
	wrapper string
	// fields that must round-trip to injectionValue in the request object.
	fields []string
	signed bool
	call   func(c *TSBClient) error
}

func payloadCases() []payloadCase {
	ctx := context.Background()
	v := injectionValue
	attrs := map[string]bool{"decrypt": true}
	policy := helpers.Policy{}
	errOnly := func(_ interface{}, _ int, err error) error { return err }
	errOnly2 := func(_ int, err error) error { return err }

	return []payloadCase{
		{"blockSync", "/v1/synchronousBlock", "blockRequest", []string{"blockKeyName"}, false,
			func(c *TSBClient) error { return errOnly2(c.blockSync(ctx, v, v)) }},
		{"AsyncBlock", "/v1/block", "blockRequest", []string{"blockKeyName"}, true,
			func(c *TSBClient) error { return errOnly(c.AsyncBlock(ctx, v, v, map[string]string{"k": v})) }},
		{"unblockSync", "/v1/synchronousUnblock", "unblockRequest", []string{"unblockKeyName"}, false,
			func(c *TSBClient) error { return errOnly2(c.unblockSync(ctx, v, v)) }},
		{"AsyncUnblock", "/v1/unblock", "unblockRequest", []string{"unblockKeyName"}, true,
			func(c *TSBClient) error { return errOnly(c.AsyncUnblock(ctx, v, v, nil)) }},
		{"modifySync", "/v1/synchronousModify", "modifyRequest", []string{"modifyKeyName"}, false,
			func(c *TSBClient) error { return errOnly2(c.modifySync(ctx, v, v, policy)) }},
		{"AsyncModify", "/v1/modify", "modifyRequest", []string{"modifyKeyName"}, true,
			func(c *TSBClient) error { return errOnly(c.AsyncModify(ctx, v, v, policy, nil)) }},
		{"UpdateKeyPassword", "/v1/key/changePassword", "", []string{"label"}, false,
			func(c *TSBClient) error { _, err := c.UpdateKeyPassword(ctx, v, v, v); return err }},
		{"CreateOrUpdateKey", "/v1/key", "", []string{"label", "algorithm", "curveOid"}, false,
			func(c *TSBClient) error {
				_, err := c.CreateOrUpdateKey(ctx, v, v, attrs, v, 2048, &policy, v, false)
				return err
			}},
		{"RemoveKey", "/v1/key/deleteKey", "", []string{"label"}, false,
			func(c *TSBClient) error { return c.RemoveKey(ctx, v, v) }},
		{"ImportKey", "/v1/key/import/plain", "", []string{"label", "algorithm", "privateKey", "publicKey", "secretKey", "certificate"}, false,
			func(c *TSBClient) error { _, err := c.ImportKey(ctx, v, v, v, v, v, attrs, v, policy); return err }},
		{"ExportKey", "/v1/key/export/plain", "", []string{"label"}, false,
			func(c *TSBClient) error { _, err := c.ExportKey(ctx, v, v); return err }},
		{"Encrypt", "/v1/encrypt", "encryptRequest", []string{"payload", "encryptKeyName", "additionalAuthenticationData"}, false,
			func(c *TSBClient) error { return errOnly(c.Encrypt(ctx, v, v, v, CipherAlgorithmAESGCM, 128, v)) }},
		{"decryptSync", "/v1/synchronousDecrypt", "decryptRequest", []string{"encryptedPayload", "decryptKeyName", "initializationVector", "additionalAuthenticationData"}, false,
			func(c *TSBClient) error { return errOnly(c.decryptSync(ctx, v, v, v, v, CipherAlgorithmAESGCM, 128, v)) }},
		{"AsyncDecrypt", "/v1/decrypt", "decryptRequest", []string{"encryptedPayload", "decryptKeyName", "initializationVector", "additionalAuthenticationData"}, true,
			func(c *TSBClient) error {
				return errOnly(c.AsyncDecrypt(ctx, v, v, v, v, CipherAlgorithmRSAPaddingOAEPWithSHA256, -1, v, nil))
			}},
		{"signSync", "/v1/synchronousSign", "signRequest", []string{"payload", "payloadType", "signKeyName", "signatureAlgorithm"}, false,
			func(c *TSBClient) error {
				return errOnly(c.signSync(ctx, v, v, v, v, SignatureAlgorithm(v), SignatureTypeDER))
			}},
		{"AsyncSign", "/v1/sign", "signRequest", []string{"payload", "payloadType", "signKeyName", "signatureAlgorithm"}, true,
			func(c *TSBClient) error {
				return errOnly(c.AsyncSign(ctx, v, v, v, v, SignatureAlgorithm(v), SignatureTypeDER, nil))
			}},
		{"Verify", "/v1/verify", "verifySignatureRequest", []string{"payload", "signKeyName", "signatureAlgorithm", "signature"}, false,
			func(c *TSBClient) error { return errOnly(c.Verify(ctx, v, v, v, SignatureAlgorithm(v), v)) }},
		{"unwrapSync", "/v1/synchronousUnwrap", "unwrapKeyRequest", []string{"wrappedKey", "label", "unwrapKeyName", "wrapMethod"}, false,
			func(c *TSBClient) error { return errOnly2(c.unwrapSync(ctx, v, v, attrs, v, v, WrapMethod(v), nil)) }},
		{"AsyncUnwrap", "/v1/unwrap", "unwrapKeyRequest", []string{"wrappedKey", "label", "unwrapKeyName", "wrapMethod"}, true,
			func(c *TSBClient) error {
				return errOnly(c.AsyncUnwrap(ctx, v, v, attrs, v, v, WrapMethod(v), nil, nil))
			}},
		{"CreateCertificate", "/v1/certificate/synchronous/request", "", []string{"signKeyName", "signatureAlgorithm"}, false,
			func(c *TSBClient) error {
				return errOnly(c.CreateCertificate(v, v, v, 1, helpers.CertificateAttributes{CommonName: v}, []string{v}, []string{v}))
			}},
		{"CreateSelfSignedCertificate", "/v1/certificate/synchronous/selfsign", "", []string{"signKeyName", "signatureAlgorithm", "commonName"}, false,
			func(c *TSBClient) error {
				return errOnly(c.CreateSelfSignedCertificate(v, v, v, 1, v, []string{v}, []string{v}, true))
			}},
		{"SignCertificate", "/v1/certificate/synchronous/sign", "", []string{"signKeyName", "signatureAlgorithm", "commonName", "certificateSigningRequest"}, false,
			func(c *TSBClient) error {
				return errOnly(c.SignCertificate(v, v, v, v, v, []string{v}, []string{v}, false))
			}},
		{"AsyncCreateCertificate", "/v1/certificate/request", "csrSignRequest", []string{"signKeyName", "signatureAlgorithm"}, true,
			func(c *TSBClient) error {
				return errOnly(c.AsyncCreateCertificate(v, v, v, 1, helpers.CertificateAttributes{CommonName: v}, []string{v}, []string{v}, map[string]string{"k": v}))
			}},
		{"AsyncSelfSignedCertificate", "/v1/certificate/selfsign", "selfSignCertificateRequest", []string{"signKeyName", "signatureAlgorithm", "commonName"}, true,
			func(c *TSBClient) error {
				return errOnly(c.AsyncSelfSignedCertificate(v, v, v, 1, v, []string{v}, []string{v}, true, nil))
			}},
		{"AsyncSignCertificate", "/v1/certificate/sign", "signCertificateRequest", []string{"signKeyName", "signatureAlgorithm", "commonName", "certificateSigningRequest"}, true,
			func(c *TSBClient) error {
				return errOnly(c.AsyncSignCertificate(v, v, v, v, v, []string{v}, []string{v}, false, nil))
			}},
		{"ImportCertificate", "/v1/certificate/import/plain", "", []string{"label", "certificate"}, false,
			func(c *TSBClient) error { return errOnly(c.ImportCertificate(v, v)) }},
	}
}

// TestRequestPayloadsEscapeUserInput sends every request type with values
// that would inject extra JSON fields if they were concatenated into the
// payload, and checks the TSB receives valid JSON with the values intact.
func TestRequestPayloadsEscapeUserInput(t *testing.T) {
	for _, withAppKey := range []bool{false, true} {
		for _, tc := range payloadCases() {
			name := tc.name
			if withAppKey {
				name += "/withAppKey"
			}
			t.Run(name, func(t *testing.T) {
				client, publicKey, captured := newCapturingTSBClient(t, withAppKey)
				requireNoError(t, tc.call(client))
				if len(*captured) != 1 {
					t.Fatalf("expected 1 request, got %d", len(*captured))
				}
				got := (*captured)[0]
				if got.path != tc.path {
					t.Fatalf("path = %q, want %q", got.path, tc.path)
				}
				if !json.Valid(got.body) {
					t.Fatalf("request body is not valid JSON: %s", got.body)
				}
				if strings.Contains(string(got.body), "\\u003c") || strings.Contains(string(got.body), "\\u0026") {
					t.Errorf("request body is HTML-escaped: %s", got.body)
				}

				var outer map[string]json.RawMessage
				requireNoError(t, json.Unmarshal(got.body, &outer))
				requestRaw := got.body
				if tc.wrapper != "" {
					wantKeys := 1
					if tc.signed {
						wantKeys = 2
					}
					if len(outer) != wantKeys {
						t.Fatalf("outer object has keys %v", keysOf(outer))
					}
					requestRaw = outer[tc.wrapper]
					if requestRaw == nil {
						t.Fatalf("missing %q in body: %s", tc.wrapper, got.body)
					}
				}

				var request map[string]interface{}
				requireNoError(t, json.Unmarshal(requestRaw, &request))
				if _, ok := request["injected"]; ok {
					t.Fatalf("injected field reached the request: %s", requestRaw)
				}
				for _, field := range tc.fields {
					if request[field] != injectionValue {
						t.Errorf("%s = %#v, want %q", field, request[field], injectionValue)
					}
				}

				if tc.signed {
					verifyRequestSignature(t, outer["requestSignature"], requestRaw, publicKey)
				}
			})
		}
	}
}

func verifyRequestSignature(t *testing.T, signatureRaw json.RawMessage, signedBytes []byte, publicKey *rsa.PublicKey) {
	t.Helper()
	if publicKey == nil {
		if string(signatureRaw) != "null" {
			t.Fatalf("requestSignature = %s, want null without an application key", signatureRaw)
		}
		return
	}
	var signature requestSignature
	requireNoError(t, json.Unmarshal(signatureRaw, &signature))
	sig, err := b64.StdEncoding.DecodeString(signature.Signature)
	requireNoError(t, err)
	digest := sha256.Sum256(signedBytes)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("request signature does not cover the request bytes that were sent: %v", err)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestRequestPayloadOptionalFields checks that optional fields keep the
// semantics of the previous hand-written payloads.
func TestRequestPayloadOptionalFields(t *testing.T) {
	ctx := context.Background()
	client, _, captured := newCapturingTSBClient(t, false)

	_, _, err := client.decryptSync(ctx, "key", "", "ct", "", CipherAlgorithmAESCBCNoPadding, 128, "")
	requireNoError(t, err)
	_, err = client.CreateOrUpdateKey(ctx, "key", "", map[string]bool{"extractable": true}, "AES", 0, &helpers.Policy{}, "", false)
	requireNoError(t, err)
	_, _, err = client.CreateCertificate("key", "", "alg", 1, helpers.CertificateAttributes{CommonName: "cn"}, nil, []string{"A", "B"})
	requireNoError(t, err)
	_, _, err = client.AsyncBlock(ctx, "key", "", nil)
	requireNoError(t, err)

	decode := func(i int) map[string]interface{} {
		var m map[string]interface{}
		requireNoError(t, json.Unmarshal((*captured)[i].body, &m))
		return m
	}

	decrypt := decode(0)["decryptRequest"].(map[string]interface{})
	for _, absent := range []string{"keyPassword", "tagLength"} {
		if _, ok := decrypt[absent]; ok {
			t.Errorf("decrypt: %s should be omitted", absent)
		}
	}
	for _, null := range []string{"initializationVector", "additionalAuthenticationData"} {
		if v, ok := decrypt[null]; !ok || v != nil {
			t.Errorf("decrypt: %s should be null, got %#v (present=%v)", null, v, ok)
		}
	}

	key := decode(1)
	for _, absent := range []string{"password", "keySize", "curveOid"} {
		if _, ok := key[absent]; ok {
			t.Errorf("create key: %s should be omitted", absent)
		}
	}
	if v, ok := key["policy"]; !ok || v != nil {
		t.Errorf("create key: policy should be null for extractable keys, got %#v", v)
	}

	cert := decode(2)
	if usage, ok := cert["keyUsage"].([]interface{}); !ok || len(usage) != 0 {
		t.Errorf("certificate: keyUsage = %#v, want []", cert["keyUsage"])
	}
	if usage, _ := cert["extendedKeyUsage"].([]interface{}); len(usage) != 2 || usage[0] != "A" || usage[1] != "B" {
		t.Errorf("certificate: extendedKeyUsage = %#v, want [A B]", cert["extendedKeyUsage"])
	}
	for _, absent := range []string{"keyPassword", "metaData", "metaDataSignature"} {
		if _, ok := cert[absent]; ok {
			t.Errorf("certificate: %s should be omitted", absent)
		}
	}

	block := decode(3)
	if v, ok := block["requestSignature"]; !ok || v != nil {
		t.Errorf("async block: requestSignature should be null without app key, got %#v", v)
	}
	blockRequest := block["blockRequest"].(map[string]interface{})
	if v, ok := blockRequest["metaDataSignature"]; !ok || v != nil {
		t.Errorf("async block: metaDataSignature should be null without app key, got %#v", v)
	}
}
