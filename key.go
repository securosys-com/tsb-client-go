// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

type changePasswordRequest struct {
	Password    []string `json:"password,omitempty"`
	NewPassword []string `json:"newPassword,omitempty"`
	Label       string   `json:"label"`
}

type createKeyRequest struct {
	Label      string          `json:"label"`
	Algorithm  string          `json:"algorithm"`
	Password   []string        `json:"password,omitempty"`
	KeySize    float64         `json:"keySize,omitempty"`
	CurveOid   string          `json:"curveOid,omitempty"`
	Attributes map[string]bool `json:"attributes"`
	Policy     *helpers.Policy `json:"policy"`
}

type deleteKeyRequest struct {
	Label    string   `json:"label"`
	Password []string `json:"password,omitempty"`
}

type importKeyRequest struct {
	Label       string          `json:"label"`
	Algorithm   string          `json:"algorithm"`
	PrivateKey  string          `json:"privateKey,omitempty"`
	PublicKey   string          `json:"publicKey,omitempty"`
	SecretKey   string          `json:"secretKey,omitempty"`
	Certificate string          `json:"certificate,omitempty"`
	Attributes  map[string]bool `json:"attributes"`
	Policy      *helpers.Policy `json:"policy"`
}

// labelPasswordRequest is used by endpoints that only need a key label and
// an optional key password.
type labelPasswordRequest struct {
	Password []string `json:"password,omitempty"`
	Label    string   `json:"label"`
}

// Function thats sends update key password request to TSB
func (c *TSBClient) UpdateKeyPassword(ctx context.Context, label string, password string, newPassword string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	jsonStr, err := marshalJSON(changePasswordRequest{
		Password:    passwordChars(password),
		NewPassword: passwordChars(newPassword),
		Label:       label,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/key/changePassword", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	_, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return "", errRes
	}
	return label, nil

}

// CreateOrUpdateKey Function thats sends create key request to TSB
func (c *TSBClient) CreateOrUpdateKey(ctx context.Context, label string, password string, attributes map[string]bool, keytype string, keySize float64, policy *helpers.Policy, curveOid string, modify bool) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if attributes["extractable"] {
		policy = nil
	}
	jsonStr, err := marshalJSON(createKeyRequest{
		Label:      label,
		Algorithm:  keytype,
		Password:   passwordChars(password),
		KeySize:    keySize,
		CurveOid:   curveOid,
		Attributes: attributes,
		Policy:     policy,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/key", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, _, err := c.doRequest(req, KeyManagementTokenName)
	if err != nil {
		if len(body) > 0 {
			var result map[string]interface{}
			errJSON := json.Unmarshal(body, &result)
			if errJSON == nil {
				return "", err
			}
		}
		return "", err
	}
	return label, nil
}

// Function thats sends delete key request to TSB
func (c *TSBClient) RemoveKey(ctx context.Context, keyLabel string, password ...string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	request := deleteKeyRequest{Label: keyLabel}
	if len(password) > 0 {
		request.Password = passwordChars(password[0])
	}
	jsonStr, err := marshalJSON(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/key/deleteKey", bytes.NewBuffer(jsonStr))
	if err != nil {
		return err
	}
	_, _, err = c.doRequest(req, KeyManagementTokenName)
	if err != nil {
		return err
	}
	return nil

}

// Function thats sends import key request to TSB
func (c *TSBClient) ImportKey(ctx context.Context, label string, privateKey string, publicKey string, secretKey string, certificate string, attributes map[string]bool, keytype string, policy helpers.Policy) (map[string]interface{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	request := importKeyRequest{
		Label:       label,
		Algorithm:   keytype,
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		SecretKey:   secretKey,
		Certificate: certificate,
		Attributes:  attributes,
		Policy:      &policy,
	}
	if attributes["extractable"] {
		request.Policy = nil
	}
	jsonStr, err := marshalJSON(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/key/import/plain", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	return response, nil

}

// Function thats sends export request to TSB
func (c *TSBClient) ExportKey(ctx context.Context, label string, password string) (map[string]interface{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	jsonStr, err := marshalJSON(labelPasswordRequest{
		Password: passwordChars(password),
		Label:    label,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/key/export/plain", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return nil, errRes
	}

	var response map[string]interface{}
	json.Unmarshal(body, &response)

	return response, nil

}

// Function thats sends get key attribute request to TSB
func (c *TSBClient) GetKey(ctx context.Context, label string, password string) (helpers.KeyAttributes, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var key helpers.KeyAttributes
	jsonStr, err := marshalJSON(labelPasswordRequest{
		Password: passwordChars(password),
		Label:    label,
	})
	if err != nil {
		return key, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/key/attributes", bytes.NewBuffer(jsonStr))
	if err != nil {
		return key, err
	}
	body, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return key, errRes
	}
	var response interface{}
	json.Unmarshal(body, &response)
	data := response.(map[string]interface{})
	jsonData := data["json"].(map[string]interface{})
	key.Algorithm = jsonData["algorithm"].(string)
	key.AlgorithmOid = jsonData["algorithmOid"].(string)
	key.CurveOid = ""
	if jsonData["derivedAttributes"] != nil {
		key.DerivedAttributes = jsonData["derivedAttributes"].(map[string]interface{})
	}
	if jsonData["id"] != nil {
		key.Id = jsonData["id"].(*string)
	}
	if fmt.Sprintf("%T", jsonData["curveOid"]) == "string" {
		key.CurveOid = jsonData["curveOid"].(string)
	}
	key.Attributes = map[string]bool{}
	attributes := jsonData["attributes"].(map[string]interface{})
	for k, e := range attributes {
		if fmt.Sprintf("%T", e) == "bool" {
			key.Attributes[k] = e.(bool)
		}
	}
	if fmt.Sprintf("%T", jsonData["keySize"]) == "float64" {
		key.KeySize = jsonData["keySize"].(float64)
	}
	key.Xml = data["xml"].(string)
	key.XmlSignature = data["xmlSignature"].(string)
	key.AttestationKeyName = data["attestationKeyName"].(string)
	key.Label = jsonData["label"].(string)
	policyString, _ := json.Marshal(jsonData["policy"])
	json.Unmarshal(policyString, &key.Policy)
	if fmt.Sprintf("%T", jsonData["publicKey"]) == "string" {
		key.PublicKey = jsonData["publicKey"].(string)
	}
	return key, nil

}

// Function thats sends get key attribute request to TSB
func (c *TSBClient) GetKeys(ctx context.Context) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.HostURL+"/v1/key", bytes.NewBuffer(nil))
	keys := []string{}
	if err != nil {
		return keys, err
	}
	body, _, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return keys, errRes
	}
	json.Unmarshal(body, &keys)
	return keys, nil

}
