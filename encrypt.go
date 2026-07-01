// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

type CipherAlgorithm string

const (
	CipherAlgorithmRSAPaddingOAEPWithSHA512 CipherAlgorithm = "RSA_PADDING_OAEP_WITH_SHA512"
	CipherAlgorithmRSA                      CipherAlgorithm = "RSA"
	CipherAlgorithmRSAPaddingOAEPWithSHA224 CipherAlgorithm = "RSA_PADDING_OAEP_WITH_SHA224"
	CipherAlgorithmRSAPaddingOAEPWithSHA256 CipherAlgorithm = "RSA_PADDING_OAEP_WITH_SHA256"
	CipherAlgorithmRSAPaddingOAEPWithSHA1   CipherAlgorithm = "RSA_PADDING_OAEP_WITH_SHA1"
	CipherAlgorithmRSAPaddingOAEP           CipherAlgorithm = "RSA_PADDING_OAEP"
	CipherAlgorithmRSAPaddingOAEPWithSHA384 CipherAlgorithm = "RSA_PADDING_OAEP_WITH_SHA384"
	CipherAlgorithmRSAPaddingPKCS           CipherAlgorithm = "RSA_PADDING_PKCS"
	CipherAlgorithmRSANoPadding             CipherAlgorithm = "RSA_NO_PADDING"
	CipherAlgorithmAESGCM                   CipherAlgorithm = "AES_GCM"
	CipherAlgorithmAESCTR                   CipherAlgorithm = "AES_CTR"
	CipherAlgorithmAESECB                   CipherAlgorithm = "AES_ECB"
	CipherAlgorithmAESCBCNoPadding          CipherAlgorithm = "AES_CBC_NO_PADDING"
	CipherAlgorithmAES                      CipherAlgorithm = "AES"
	CipherAlgorithmChaCha20                 CipherAlgorithm = "CHACHA20"
	CipherAlgorithmChaCha20AEAD             CipherAlgorithm = "CHACHA20_AEAD"
	CipherAlgorithmCamellia                 CipherAlgorithm = "CAMELLIA"
	CipherAlgorithmCamelliaCBCNoPadding     CipherAlgorithm = "CAMELLIA_CBC_NO_PADDING"
	CipherAlgorithmCamelliaECB              CipherAlgorithm = "CAMELLIA_ECB"
	CipherAlgorithmTDEACBC                  CipherAlgorithm = "TDEA_CBC"
	CipherAlgorithmTDEAECB                  CipherAlgorithm = "TDEA_ECB"
	CipherAlgorithmTDEACBCNoPadding         CipherAlgorithm = "TDEA_CBC_NO_PADDING"
)

var RSA_CIPHER_ALGORITHM = []CipherAlgorithm{
	CipherAlgorithmRSAPaddingOAEPWithSHA512,
	CipherAlgorithmRSA,
	CipherAlgorithmRSAPaddingOAEPWithSHA224,
	CipherAlgorithmRSAPaddingOAEPWithSHA256,
	CipherAlgorithmRSAPaddingOAEPWithSHA1,
	CipherAlgorithmRSAPaddingOAEP,
	CipherAlgorithmRSAPaddingOAEPWithSHA384,
	CipherAlgorithmRSAPaddingPKCS,
	CipherAlgorithmRSANoPadding,
}

var AES_CIPHER_ALGORITHM = []CipherAlgorithm{
	CipherAlgorithmAESGCM,
	CipherAlgorithmAESCTR,
	CipherAlgorithmAESECB,
	CipherAlgorithmAESCBCNoPadding,
	CipherAlgorithmAES,
}

var CHACHA20_CIPHER_ALGORITHM = []CipherAlgorithm{
	CipherAlgorithmChaCha20,
	CipherAlgorithmChaCha20AEAD,
}

var CAMELLIA_CIPHER_ALGORITHM = []CipherAlgorithm{
	CipherAlgorithmCamellia,
	CipherAlgorithmCamelliaCBCNoPadding,
	CipherAlgorithmCamelliaECB,
}

var TDEA_CIPHER_ALGORITHM = []CipherAlgorithm{
	CipherAlgorithmTDEACBC,
	CipherAlgorithmTDEAECB,
	CipherAlgorithmTDEACBCNoPadding,
}

// Function thats sends asynchronous decrypt request to TSB
func (c *TSBClient) AsyncDecrypt(ctx context.Context, label string, password string, cipertext string, vector string, cipherAlgorithm CipherAlgorithm, tagLength int, additionalAuthenticationData string, customMetaData map[string]string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))

	var additionalMetaDataInfo map[string]string = make(map[string]string)

	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Decrypt", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	vectorString := `"` + vector + `"`
	if vector == "" {
		vectorString = "null"
	}
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == CipherAlgorithmAESGCM {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
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
		"encryptedPayload": "` + cipertext + `",
		` + passwordString + `
		"decryptKeyName": "` + label + `",
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `,
		"cipherAlgorithm": "` + string(cipherAlgorithm) + `",
		"initializationVector": ` + vectorString + `,
		` + tagLengthString + `
		"additionalAuthenticationData":` + additionalAuthenticationDataString + `
	  }`

	var jsonStr = []byte(helpers.MinifyJson(`{
		"decryptRequest": ` + helpers.MinifyJson(requestJson) + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
	  }`))

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/decrypt", bytes.NewBuffer(jsonStr))
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
	return result["decryptRequestId"].(string), code, nil
	// return response, nil

}

// Function thats sends decrypt request to TSB
func (c *TSBClient) Decrypt(ctx context.Context, label string, password string, cipertext string, vector string, cipherAlgorithm CipherAlgorithm, tagLength int, additionalAuthenticationData string) (*helpers.DecryptResponse, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	vectorString := `"` + vector + `"`
	if vector == "" {
		vectorString = "null"
	}
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == CipherAlgorithmAESGCM {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"decryptRequest": {
		  "encryptedPayload": "` + cipertext + `",
		  ` + passwordString + `	
		  "decryptKeyName": "` + label + `",
		  "cipherAlgorithm": "` + string(cipherAlgorithm) + `",
		  "initializationVector": ` + vectorString + `,
		  ` + tagLengthString + `
		  "additionalAuthenticationData":` + additionalAuthenticationDataString + `
		}
	  }`)
	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/synchronousDecrypt", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var decryptResponse helpers.DecryptResponse
	errJSON := json.Unmarshal(body, &decryptResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}
	return &decryptResponse, code, nil

}

// Function thats send encrypt request to TSB
func (c *TSBClient) Encrypt(ctx context.Context, label string, password string, payload string, cipherAlgorithm CipherAlgorithm, tagLength int, additionalAuthenticationData string) (*helpers.EncryptResponse, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == CipherAlgorithmAESGCM {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"encryptRequest": {
		  "payload": "` + payload + `",
		  ` + passwordString + `
		  "encryptKeyName": "` + label + `",
		  "cipherAlgorithm": "` + string(cipherAlgorithm) + `",
		  ` + tagLengthString + `
		  "additionalAuthenticationData":` + additionalAuthenticationDataString + `
		}
	  }`)
	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/encrypt", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var encryptResponse helpers.EncryptResponse
	errJSON := json.Unmarshal(body, &encryptResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}
	return &encryptResponse, code, nil

}
