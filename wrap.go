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

type WrapMethod string

const (
	WrapMethodAES       WrapMethod = "AES_WRAP"
	WrapMethodAESDSA    WrapMethod = "AES_WRAP_DSA"
	WrapMethodAESEC     WrapMethod = "AES_WRAP_EC"
	WrapMethodAESED     WrapMethod = "AES_WRAP_ED"
	WrapMethodAESRSA    WrapMethod = "AES_WRAP_RSA"
	WrapMethodAESBLS    WrapMethod = "AES_WRAP_BLS"
	WrapMethodAESPad    WrapMethod = "AES_WRAP_PAD"
	WrapMethodAESPadDSA WrapMethod = "AES_WRAP_PAD_DSA"
	WrapMethodAESPadEC  WrapMethod = "AES_WRAP_PAD_EC"
	WrapMethodAESPadED  WrapMethod = "AES_WRAP_PAD_ED"
	WrapMethodAESPadRSA WrapMethod = "AES_WRAP_PAD_RSA"
	WrapMethodAESPadBLS WrapMethod = "AES_WRAP_PAD_BLS"
	WrapMethodRSAPad    WrapMethod = "RSA_WRAP_PAD"
	WrapMethodRSAOAEP   WrapMethod = "RSA_WRAP_OAEP"
	WrapMethodMLKEM512  WrapMethod = "ML-KEM-512"
	WrapMethodMLKEM768  WrapMethod = "ML-KEM-768"
	WrapMethodMLKEM1024 WrapMethod = "ML-KEM-1024"
)

var AES_WRAP_METHODS = []WrapMethod{
	WrapMethodAES,
	WrapMethodAESDSA,
	WrapMethodAESEC,
	WrapMethodAESED,
	WrapMethodAESRSA,
	WrapMethodAESBLS,
	WrapMethodAESPad,
	WrapMethodAESPadDSA,
	WrapMethodAESPadEC,
	WrapMethodAESPadED,
	WrapMethodAESPadRSA,
	WrapMethodAESPadBLS,
}

var RSA_WRAP_METHODS = []WrapMethod{
	WrapMethodRSAPad,
	WrapMethodRSAOAEP,
}

var ML_KEM_WRAP_METHODS = []WrapMethod{
	WrapMethodMLKEM512,
	WrapMethodMLKEM768,
	WrapMethodMLKEM1024,
}

// Function thats send wrap request to TSB
func (c *TSBClient) Wrap(wrapKeyName string, wrapKeyPassword string, keyToBeWrapped string, keyToBeWrappedPassword string, wrapMethod WrapMethod) (*helpers.WrapResponse, int, error) {
	wrapKeyRequest := map[string]interface{}{
		"keyToBeWrapped": keyToBeWrapped,
		"wrapKeyName":    wrapKeyName,
		"wrapMethod":     string(wrapMethod),
	}
	if keyToBeWrappedPassword != "" {
		wrapKeyRequest["keyToBeWrappedPassword"] = helpers.StringToCharArray(keyToBeWrappedPassword)
	}
	if wrapKeyPassword != "" {
		wrapKeyRequest["wrapKeyPassword"] = helpers.StringToCharArray(wrapKeyPassword)
	}

	jsonStr, err := json.Marshal(map[string]interface{}{
		"wrapKeyRequest": wrapKeyRequest,
	})
	if err != nil {
		return nil, 500, err
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", c.HostURL+"/v1/wrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.WrapResponse
	// response.KeyID = signKeyName
	// response.CertificateRequest = string(body)
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// AsyncUnwrap submits an asynchronous unwrap request to TSB.
func (c *TSBClient) AsyncUnwrap(ctx context.Context, wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod WrapMethod, policy *helpers.Policy, customMetaData map[string]string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(unwrapKeyPassword))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	additionalMetaDataInfo["wrapped key"] = wrappedKey
	additionalMetaDataInfo["new key label"] = label
	additionalMetaDataInfo["wrap method"] = string(wrapMethod)
	additionalMetaDataInfo["attributes"] = fmt.Sprintf("%v", attributes)

	metaDataB64, metaDataSignature, err := c.PrepareMetaData("UnWrap", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"unwrapKeyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{
		"wrappedKey": "` + wrappedKey + `",
		"label": "` + label + `",
		"unwrapKeyName": "` + unwrapKeyName + `",
		` + passwordString + `
		"wrapMethod": "` + string(wrapMethod) + `",
		"attributes": ` + helpers.PrepareAttributes(attributes) + `,
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `
		}`
	var jsonStr = []byte(helpers.MinifyJson(`{
			"unwrapKeyRequest": ` + requestJson + `,
			"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
		}`))
	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/unwrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return "", code, errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", code, errJSON
	}
	return result["unwrapRequestId"].(string), code, nil
}

// Unwrap unwraps a key. It uses the synchronous endpoint when the unwrapping
// key has no policy and transparently submits and waits for an asynchronous
// request when approvals are required.
func (c *TSBClient) Unwrap(ctx context.Context, wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod WrapMethod, policy *helpers.Policy) (int, error) {
	key, err := c.GetKey(ctx, unwrapKeyName, unwrapKeyPassword)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if key.Policy != nil {
		requestID, code, err := c.AsyncUnwrap(ctx, wrappedKey, label, attributes, unwrapKeyName, unwrapKeyPassword, wrapMethod, policy, map[string]string{})
		if err != nil {
			return code, err
		}
		request, code, err := c.WaitForRequest(ctx, requestID)
		if err != nil {
			return code, err
		}
		if request.Status != "EXECUTED" {
			return code, fmt.Errorf("unwrap request %s completed with status %s", requestID, request.Status)
		}
		return code, nil
	}

	return c.unwrapSync(ctx, wrappedKey, label, attributes, unwrapKeyName, unwrapKeyPassword, wrapMethod, policy)
}

func (c *TSBClient) unwrapSync(ctx context.Context, wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod WrapMethod, policy *helpers.Policy) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(unwrapKeyPassword))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"unwrapKeyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"unwrapKeyRequest": {
		"wrappedKey": "` + wrappedKey + `",
		"label": "` + label + `",
		"unwrapKeyName": "` + unwrapKeyName + `",
		` + passwordString + `
		"wrapMethod": "` + string(wrapMethod) + `",
		"attributes": ` + helpers.PrepareAttributes(attributes) + `
		}}`)
	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/synchronousUnwrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, err := c.doRequest(req, KeyOperationTokenName)
	return code, err
}
