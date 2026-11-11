// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

// requestSignature is the "requestSignature" object sent with asynchronous
// requests.
type requestSignature struct {
	Signature       string `json:"signature"`
	DigestAlgorithm string `json:"digestAlgorithm"`
	PublicKey       string `json:"publicKey"`
}

// marshalJSON encodes v as compact JSON. Every request body must be built with
// this function (never by string concatenation) so that user-supplied values
// are always escaped correctly.
//
// HTML escaping is disabled so the bytes on the wire match what the TSB
// receives and verifies (e.g. "&" is not rewritten to "&").
func marshalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a newline.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// signRequest returns the JSON "requestSignature" value for the given
// (already marshalled) request. It returns JSON null when no application key
// pair is configured.
func (c *TSBClient) signRequest(requestJSON []byte) (json.RawMessage, error) {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil || c.Auth.ApplicationKeyPair.PublicKey == nil {
		return json.RawMessage("null"), nil
	}
	signature, err := c.SignData(requestJSON)
	if err != nil {
		return nil, err
	}
	return marshalJSON(requestSignature{
		Signature:       *signature,
		DigestAlgorithm: "SHA-256",
		PublicKey:       *c.Auth.ApplicationKeyPair.PublicKey,
	})
}

// signedRequestBody builds {"<requestKey>": request, "requestSignature": ...}.
//
// The request is marshalled exactly once and those bytes are both signed and
// embedded verbatim in the body, so the signature always covers precisely
// what is sent.
func (c *TSBClient) signedRequestBody(requestKey string, request interface{}) ([]byte, error) {
	requestJSON, err := marshalJSON(request)
	if err != nil {
		return nil, err
	}
	signature, err := c.signRequest(requestJSON)
	if err != nil {
		return nil, err
	}
	return marshalJSON(map[string]json.RawMessage{
		requestKey:         requestJSON,
		"requestSignature": signature,
	})
}

// wrappedRequestBody builds {"<requestKey>": request} for synchronous
// endpoints that expect the request nested under a single key.
func wrappedRequestBody(requestKey string, request interface{}) ([]byte, error) {
	return marshalJSON(map[string]interface{}{requestKey: request})
}

// passwordChars converts a password into the character array representation
// expected by the TSB. An empty password yields nil so that fields tagged
// with omitempty are left out, matching previous behaviour.
func passwordChars(password string) []string {
	if password == "" {
		return nil
	}
	return helpers.StringToCharArray(password)
}

// nullIfEmpty returns nil (encoded as JSON null) for an empty string.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nonNilStrings ensures a nil slice is encoded as [] rather than null.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
