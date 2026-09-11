// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/securosys-com/tsb-client-go/helpers"
)

// AsyncDecapsulate creates an asynchronous ML-KEM decapsulation request.
func (c *TSBClient) AsyncDecapsulate(ctx context.Context, label string, password string, ciphertext string, customMetaData map[string]string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	metaData, metaDataSignature, err := c.PrepareMetaData("Decapsulate", map[string]string{}, customMetaData)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	request := map[string]interface{}{
		"decapsulationKeyName": label,
		"ciphertext":           ciphertext,
		"metaData":             metaData,
		"metaDataSignature":    metaDataSignature,
	}
	if password != "" {
		request["keyPassword"] = helpers.StringToCharArray(password)
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	var requestSignature interface{}
	if err := json.Unmarshal(c.GenerateRequestSignature(string(requestJSON)), &requestSignature); err != nil {
		return "", http.StatusInternalServerError, err
	}
	bodyJSON, err := json.Marshal(map[string]interface{}{
		"decapsulationRequest": request,
		"requestSignature":     requestSignature,
	})
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HostURL+"/v1/decapsulate", bytes.NewReader(bodyJSON))
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	body, code, err := c.doRequest(req, KeyOperationTokenName)
	if err != nil {
		return "", code, err
	}
	var response helpers.DecapsulationRequestResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", code, err
	}
	return response.DecapsulationRequestID, code, nil
}

// Decapsulate returns the recovered shared secret. It uses the synchronous TSB
// endpoint for a key without a policy and transparently submits and waits for
// an asynchronous request when approvals are required.
func (c *TSBClient) Decapsulate(ctx context.Context, label string, password string, ciphertext string) (*helpers.DecapsulationResponse, int, error) {
	key, err := c.GetKey(ctx, label, password)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if key.Policy != nil {
		requestID, code, err := c.AsyncDecapsulate(ctx, label, password, ciphertext, map[string]string{})
		if err != nil {
			return nil, code, err
		}
		request, code, err := c.WaitForRequest(ctx, requestID)
		if err != nil {
			return nil, code, err
		}
		if request.Status != "EXECUTED" {
			return nil, code, fmt.Errorf("decapsulation request %s completed with status %s", requestID, request.Status)
		}
		return &helpers.DecapsulationResponse{SharedSecret: request.Result}, code, nil
	}

	return c.decapsulateSync(ctx, label, password, ciphertext)
}

func (c *TSBClient) decapsulateSync(ctx context.Context, label string, password string, ciphertext string) (*helpers.DecapsulationResponse, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	request := map[string]interface{}{
		"decapsulationKeyName": label,
		"ciphertext":           ciphertext,
	}
	if password != "" {
		request["keyPassword"] = helpers.StringToCharArray(password)
	}
	bodyJSON, err := json.Marshal(map[string]interface{}{"decapsulationRequest": request})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HostURL+"/v1/synchronousDecapsulate", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	body, code, err := c.doRequest(req, KeyOperationTokenName)
	if err != nil {
		return nil, code, err
	}
	var response helpers.DecapsulationResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, code, err
	}
	return &response, code, nil
}

// Encapsulate generates and encapsulates an ML-KEM shared secret using a public key.
func (c *TSBClient) Encapsulate(ctx context.Context, publicKey string) (*helpers.EncapsulationResponse, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	bodyJSON, err := json.Marshal(map[string]string{"publicKey": publicKey})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HostURL+"/v1/encapsulate", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	body, code, err := c.doRequest(req, KeyOperationTokenName)
	if err != nil {
		return nil, code, err
	}
	var response helpers.EncapsulationResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, code, err
	}
	return &response, code, nil
}
