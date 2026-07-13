// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/securosys-com/tsb-client-go/helpers"
)

// Function thats send block request to TSB
func (c *TSBClient) Block(ctx context.Context, label string, password string) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"blockRequest": {
		  ` + passwordString + `
		  "blockKeyName": "` + label + `"
		}
	  }`)

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/synchronousBlock", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return code, errRes
	}
	return code, nil

}

// Function thats send asynchronous block request to TSB
func (c *TSBClient) AsyncBlock(ctx context.Context, label string, password string, customMetaData map[string]string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Block", additionalMetaDataInfo, customMetaData)
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
		"blockKeyName": "` + label + `",
		` + passwordString + `	  
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `
	  }`
	var jsonStr = []byte(helpers.MinifyJson(`{
		"blockRequest": ` + requestJson + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `

	  }`))

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/block", bytes.NewBuffer(jsonStr))
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
	return result["blockKeyRequestId"].(string), code, nil

}
