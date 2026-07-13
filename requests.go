// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

// Function thats sends get request to TSB
func (c *TSBClient) GetRequest(ctx context.Context, id string) (*helpers.RequestResponse, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.HostURL+"/v1/request/"+id, bytes.NewBuffer(nil))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var requestResponse helpers.RequestResponse
	errJSON := json.Unmarshal(body, &requestResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}
	return &requestResponse, code, nil
}

// Function thats sends delete request to TSB
func (c *TSBClient) RemoveRequest(ctx context.Context, id string) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", c.HostURL+"/v1/request/"+id, nil)
	if err != nil {
		return 500, err
	}
	_, code, errReq := c.doRequest(req, KeyOperationTokenName)
	if code == 404 || code == 500 {
		return code, nil
	}
	if errReq != nil {
		return code, errReq
	}
	return code, nil

}
