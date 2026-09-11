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

// Unblock unblocks a key. It uses the synchronous endpoint for a key without a
// policy and transparently submits and waits for an asynchronous request when
// approvals are required.
func (c *TSBClient) Unblock(ctx context.Context, label string, password string) (int, error) {
	key, err := c.GetKey(ctx, label, password)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if key.Policy != nil {
		requestID, code, err := c.AsyncUnblock(ctx, label, password, map[string]string{})
		if err != nil {
			return code, err
		}
		request, code, err := c.WaitForRequest(ctx, requestID)
		if err != nil {
			return code, err
		}
		if request.Status != "EXECUTED" {
			return code, fmt.Errorf("unblock request %s completed with status %s", requestID, request.Status)
		}
		return code, nil
	}

	return c.unblockSync(ctx, label, password)
}

func (c *TSBClient) unblockSync(ctx context.Context, label string, password string) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"unblockRequest": {
		` + passwordString + `
		  "unblockKeyName": "` + label + `"
		}
	  }`)

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/synchronousUnblock", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return code, errRes
	}
	return code, nil

}

// AsyncUnblock submits an asynchronous unblock request to TSB.
func (c *TSBClient) AsyncUnblock(ctx context.Context, label string, password string, customMetaData map[string]string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("UnBlock", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{
		"unblockKeyName": "` + label + `",
		` + passwordString + `
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `
	  }`
	var jsonStr = []byte(helpers.MinifyJson(`{
		"unblockRequest": ` + requestJson + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
	  }`))

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/unblock", bytes.NewBuffer(jsonStr))
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
	return result["unblockKeyRequestId"].(string), code, nil
}
