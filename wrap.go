// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
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

// Function thats send wrap request to TSB
func (c *TSBClient) Wrap(wrapKeyName string, wrapKeyPassword string, keyToBeWrapped string, keyToBeWrappedPassword string, wrapMethod WrapMethod) (*helpers.WrapResponse, int, error) {
	keyToBeWrappedPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyToBeWrappedPassword))
	wrapKeyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(wrapKeyPassword))
	keyToBeWrappedPasswordString := ""
	if len(keyToBeWrappedPasswordJson) > 2 {
		keyToBeWrappedPasswordString = `"keyToBeWrappedPassword": ` + string(keyToBeWrappedPasswordJson) + `,`

	}
	wrapKeyPasswordString := ""
	if len(wrapKeyPasswordJson) > 2 {
		wrapKeyPasswordString = `"wrapKeyPassword": ` + string(wrapKeyPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"wrapKeyRequest": {
		"keyToBeWrapped": "` + keyToBeWrapped + `",
		` + keyToBeWrappedPasswordString + `
		  "wrapKeyName": "` + wrapKeyName + `",
		  ` + wrapKeyPasswordString + `
		  "wrapMethod":"` + string(wrapMethod) + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/wrap", bytes.NewBuffer(jsonStr))
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

// Function thats sends asynchronous unwrap request to TSB
func (c *TSBClient) AsyncUnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod WrapMethod, policy *helpers.Policy, customMetaData map[string]string) (string, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(unwrapKeyPassword))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	additionalMetaDataInfo["wrapped key"] = wrappedKey
	additionalMetaDataInfo["new key label"] = label
	additionalMetaDataInfo["wrap method"] = string(wrapMethod)
	additionalMetaDataInfo["attributes"] = fmt.Sprintf("%v", attributes)
	var policyString string
	if policy == nil {
		policyString = string(`,"policy":null`)
	} else {
		policyJson, _ := json.Marshal(*policy)
		policyString = string(`,"policy":` + string(policyJson))
	}

	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
	//Only for asychronous unwrap
	policyString = string(``)
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
		"metaDataSignature": ` + metaDataSignatureString + `` + policyString + `
		}`
	var jsonStr = []byte(helpers.MinifyJson(`{
			"unwrapKeyRequest": ` + requestJson + `,
			"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
		}`))
	req, err := http.NewRequest("POST", c.HostURL+"/v1/unwrap", bytes.NewBuffer(jsonStr))
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

// Function thats sends unwrap request to TSB
func (c *TSBClient) UnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod WrapMethod, policy *helpers.Policy) (int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(unwrapKeyPassword))
	var policyString string
	if policy == nil {
		policyString = string(`,"policy":null`)
	} else {
		policyJson, _ := json.Marshal(policy)
		policyString = string(`,"policy":` + string(policyJson))
	}
	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
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
		"attributes": ` + helpers.PrepareAttributes(attributes) + policyString + `
		}}`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousUnwrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, err := c.doRequest(req, KeyOperationTokenName)
	return code, err
}
