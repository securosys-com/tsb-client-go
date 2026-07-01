// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"encoding/json"
	"errors"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

// securosysClient creates an object storing
// the client.
type SecurosysClient struct {
	*TSBClient
}

// NewClient creates a new client to access Securosys TSB.
func NewClient(config *helpers.SecurosysConfig) (*SecurosysClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}
	bytes, _ := json.Marshal(config)
	var mappedConfig map[string]string
	json.Unmarshal(bytes, &mappedConfig)
	var keyPair KeyPair
	json.Unmarshal([]byte(mappedConfig["applicationKeyPair"]), &keyPair)

	var apiKeys ApiKeyTypes
	json.Unmarshal([]byte(mappedConfig["apiKeys"]), &apiKeys)
	c, err := NewTSBClient(mappedConfig["restapi"], AuthStruct{
		AuthType:           mappedConfig["auth"],
		CertPath:           mappedConfig["certpath"],
		KeyPath:            mappedConfig["keypath"],
		BearerToken:        mappedConfig["bearertoken"],
		ApplicationKeyPair: keyPair,
		ApiKeys:            apiKeys,
		AppName:            "OpenBao - Securosys HSM KMS",
	})
	if err != nil {
		return nil, err
	}
	return &SecurosysClient{c}, nil
}
