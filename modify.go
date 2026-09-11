// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

// Modify updates a key policy. It uses the synchronous endpoint for a key
// without a policy and transparently submits and waits for an asynchronous
// request when approvals are required.
func (c *TSBClient) Modify(ctx context.Context, label string, password string, policy helpers.Policy) (int, error) {
	key, err := c.GetKey(ctx, label, password)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if key.Policy != nil {
		requestID, code, err := c.AsyncModify(ctx, label, password, policy, map[string]string{})
		if err != nil {
			return code, err
		}
		request, code, err := c.WaitForRequest(ctx, requestID)
		if err != nil {
			return code, err
		}
		if request.Status != "EXECUTED" {
			return code, fmt.Errorf("modify request %s completed with status %s", requestID, request.Status)
		}
		return code, nil
	}

	return c.modifySync(ctx, label, password, policy)
}

func (c *TSBClient) modifySync(ctx context.Context, label string, password string, policy helpers.Policy) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"modifyRequest":{
			` + passwordString + `
			"modifyKeyName": "` + label + `"
			` + policyString + `}
		}`)

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/synchronousModify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return code, errRes
	}
	return code, nil

}

// Function thats send asynchronous request modify key to TSB
func (c *TSBClient) AsyncModify(ctx context.Context, label string, password string, policy helpers.Policy, customMetaData map[string]string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Modify", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{"modifyKeyName": "` + label + `",
		` + passwordString + `
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `
		  ` + policyString + `}`
	var jsonStr = []byte(helpers.MinifyJson(`{
		"modifyRequest":` + requestJson + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
		}`))
	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/modify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", 500, err
	}
	body, code, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return "", code, errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", code, errJSON
	}
	return result["modifyKeyRequestId"].(string), code, nil

}
