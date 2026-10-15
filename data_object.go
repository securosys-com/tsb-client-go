// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

const dataObjectPath = "/v1/dataObject"

// CreateDataObject stores a data object on the HSM. The object's Value must be
// base64 encoded.
func (c *TSBClient) CreateDataObject(ctx context.Context, dataObject helpers.DataObject) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	payload, err := json.Marshal(dataObject)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HostURL+dataObjectPath, bytes.NewReader(payload))
	if err != nil {
		return http.StatusInternalServerError, err
	}

	_, code, err := c.doRequest(req, KeyManagementTokenName)
	return code, err
}

// GetDataObject retrieves a data object by name from the HSM.
func (c *TSBClient) GetDataObject(ctx context.Context, name string) (*helpers.DataObject, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.dataObjectURL(name), nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	body, code, err := c.doRequest(req, KeyManagementTokenName)
	if err != nil {
		return nil, code, err
	}

	var dataObject helpers.DataObject
	if err := json.Unmarshal(body, &dataObject); err != nil {
		return nil, code, err
	}
	return &dataObject, code, nil
}

// DeleteDataObject removes a data object by name from the HSM.
func (c *TSBClient) DeleteDataObject(ctx context.Context, name string) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.dataObjectURL(name), nil)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	_, code, err := c.doRequest(req, KeyManagementTokenName)
	return code, err
}

func (c *TSBClient) dataObjectURL(name string) string {
	return c.HostURL + dataObjectPath + "/" + url.PathEscape(name)
}
