// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Block blocks a key. It uses the synchronous endpoint for a key without a
// policy and transparently submits and waits for an asynchronous request when
// approvals are required.
func (c *TSBClient) Block(ctx context.Context, label string, password string) (int, error) {
	key, err := c.GetKey(ctx, label, password)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if key.Policy != nil {
		requestID, code, err := c.AsyncBlock(ctx, label, password, map[string]string{})
		if err != nil {
			return code, err
		}
		request, code, err := c.WaitForRequest(ctx, requestID)
		if err != nil {
			return code, err
		}
		if request.Status != "EXECUTED" {
			return code, fmt.Errorf("block request %s completed with status %s", requestID, request.Status)
		}
		return code, nil
	}

	return c.blockSync(ctx, label, password)
}

type blockRequest struct {
	KeyPassword  []string `json:"keyPassword,omitempty"`
	BlockKeyName string   `json:"blockKeyName"`
}

type asyncBlockRequest struct {
	BlockKeyName      string   `json:"blockKeyName"`
	KeyPassword       []string `json:"keyPassword,omitempty"`
	MetaData          string   `json:"metaData"`
	MetaDataSignature *string  `json:"metaDataSignature"`
}

func (c *TSBClient) blockSync(ctx context.Context, label string, password string) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	jsonStr, err := wrappedRequestBody("blockRequest", blockRequest{
		KeyPassword:  passwordChars(password),
		BlockKeyName: label,
	})
	if err != nil {
		return 500, err
	}

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

	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Block", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	jsonStr, err := c.signedRequestBody("blockRequest", asyncBlockRequest{
		BlockKeyName:      label,
		KeyPassword:       passwordChars(password),
		MetaData:          metaDataB64,
		MetaDataSignature: metaDataSignature,
	})
	if err != nil {
		return "", 500, err
	}

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
