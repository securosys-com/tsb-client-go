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

type SignatureType string
type SignatureAlgorithm string

const (
	SignatureTypeDER SignatureType = "DER"
	SignatureTypeETH SignatureType = "ETH"
	SignatureTypeRAW SignatureType = "RAW"
)

const (
	SignatureAlgorithmSHA224WithRSAPSS      SignatureAlgorithm = "SHA224_WITH_RSA_PSS"
	SignatureAlgorithmSHA256WithRSAPSS      SignatureAlgorithm = "SHA256_WITH_RSA_PSS"
	SignatureAlgorithmSHA384WithRSAPSS      SignatureAlgorithm = "SHA384_WITH_RSA_PSS"
	SignatureAlgorithmSHA512WithRSAPSS      SignatureAlgorithm = "SHA512_WITH_RSA_PSS"
	SignatureAlgorithmNoneWithRSA           SignatureAlgorithm = "NONE_WITH_RSA"
	SignatureAlgorithmNoneWithRSAPSS        SignatureAlgorithm = "NONE_WITH_RSA_PSS"
	SignatureAlgorithmSHA224WithRSA         SignatureAlgorithm = "SHA224_WITH_RSA"
	SignatureAlgorithmSHA256WithRSA         SignatureAlgorithm = "SHA256_WITH_RSA"
	SignatureAlgorithmSHA384WithRSA         SignatureAlgorithm = "SHA384_WITH_RSA"
	SignatureAlgorithmSHA512WithRSA         SignatureAlgorithm = "SHA512_WITH_RSA"
	SignatureAlgorithmNoneSHA224WithRSA     SignatureAlgorithm = "NONESHA224_WITH_RSA"
	SignatureAlgorithmNoneSHA256WithRSA     SignatureAlgorithm = "NONESHA256_WITH_RSA"
	SignatureAlgorithmNoneSHA384WithRSA     SignatureAlgorithm = "NONESHA384_WITH_RSA"
	SignatureAlgorithmNoneSHA512WithRSA     SignatureAlgorithm = "NONESHA512_WITH_RSA"
	SignatureAlgorithmNoneSHA224WithRSAPSS  SignatureAlgorithm = "NONESHA224_WITH_RSA_PSS"
	SignatureAlgorithmNoneSHA256WithRSAPSS  SignatureAlgorithm = "NONESHA256_WITH_RSA_PSS"
	SignatureAlgorithmNoneSHA384WithRSAPSS  SignatureAlgorithm = "NONESHA384_WITH_RSA_PSS"
	SignatureAlgorithmNoneSHA512WithRSAPSS  SignatureAlgorithm = "NONESHA512_WITH_RSA_PSS"
	SignatureAlgorithmSHA1WithRSA           SignatureAlgorithm = "SHA1_WITH_RSA"
	SignatureAlgorithmNoneSHA1WithRSA       SignatureAlgorithm = "NONESHA1_WITH_RSA"
	SignatureAlgorithmSHA1WithRSAPSS        SignatureAlgorithm = "SHA1_WITH_RSA_PSS"
	SignatureAlgorithmNoneWithDSA           SignatureAlgorithm = "NONE_WITH_DSA"
	SignatureAlgorithmSHA224WithDSA         SignatureAlgorithm = "SHA224_WITH_DSA"
	SignatureAlgorithmSHA256WithDSA         SignatureAlgorithm = "SHA256_WITH_DSA"
	SignatureAlgorithmSHA384WithDSA         SignatureAlgorithm = "SHA384_WITH_DSA"
	SignatureAlgorithmSHA512WithDSA         SignatureAlgorithm = "SHA512_WITH_DSA"
	SignatureAlgorithmSHA1WithDSA           SignatureAlgorithm = "SHA1_WITH_DSA"
	SignatureAlgorithmNoneWithECDSA         SignatureAlgorithm = "NONE_WITH_ECDSA"
	SignatureAlgorithmSHA1WithECDSA         SignatureAlgorithm = "SHA1_WITH_ECDSA"
	SignatureAlgorithmSHA224WithECDSA       SignatureAlgorithm = "SHA224_WITH_ECDSA"
	SignatureAlgorithmSHA256WithECDSA       SignatureAlgorithm = "SHA256_WITH_ECDSA"
	SignatureAlgorithmDoubleSHA256WithECDSA SignatureAlgorithm = "DOUBLE_SHA256_WITH_ECDSA"
	SignatureAlgorithmSHA384WithECDSA       SignatureAlgorithm = "SHA384_WITH_ECDSA"
	SignatureAlgorithmSHA512WithECDSA       SignatureAlgorithm = "SHA512_WITH_ECDSA"
	SignatureAlgorithmSHA3224WithECDSA      SignatureAlgorithm = "SHA3224_WITH_ECDSA"
	SignatureAlgorithmSHA3256WithECDSA      SignatureAlgorithm = "SHA3256_WITH_ECDSA"
	SignatureAlgorithmSHA3384WithECDSA      SignatureAlgorithm = "SHA3384_WITH_ECDSA"
	SignatureAlgorithmSHA3512WithECDSA      SignatureAlgorithm = "SHA3512_WITH_ECDSA"
	SignatureAlgorithmSHA256WithECDSADet    SignatureAlgorithm = "SHA256_WITH_ECDSA_DETERMINISTIC"
	SignatureAlgorithmKECCAK224WithECDSA    SignatureAlgorithm = "KECCAK224_WITH_ECDSA"
	SignatureAlgorithmKECCAK256WithECDSA    SignatureAlgorithm = "KECCAK256_WITH_ECDSA"
	SignatureAlgorithmKECCAK384WithECDSA    SignatureAlgorithm = "KECCAK384_WITH_ECDSA"
	SignatureAlgorithmKECCAK512WithECDSA    SignatureAlgorithm = "KECCAK512_WITH_ECDSA"
	SignatureAlgorithmEDDSA                 SignatureAlgorithm = "EDDSA"
	SignatureAlgorithmBLS                   SignatureAlgorithm = "BLS"
)

var RSA_SIGNATURE_ALGORITHM = []SignatureAlgorithm{
	SignatureAlgorithmSHA224WithRSAPSS,
	SignatureAlgorithmSHA256WithRSAPSS,
	SignatureAlgorithmSHA384WithRSAPSS,
	SignatureAlgorithmSHA512WithRSAPSS,
	SignatureAlgorithmNoneWithRSA,
	SignatureAlgorithmNoneWithRSAPSS,
	SignatureAlgorithmSHA224WithRSA,
	SignatureAlgorithmSHA256WithRSA,
	SignatureAlgorithmSHA384WithRSA,
	SignatureAlgorithmSHA512WithRSA,
	SignatureAlgorithmNoneSHA224WithRSA,
	SignatureAlgorithmNoneSHA256WithRSA,
	SignatureAlgorithmNoneSHA384WithRSA,
	SignatureAlgorithmNoneSHA512WithRSA,
	SignatureAlgorithmNoneSHA224WithRSAPSS,
	SignatureAlgorithmNoneSHA256WithRSAPSS,
	SignatureAlgorithmNoneSHA384WithRSAPSS,
	SignatureAlgorithmNoneSHA512WithRSAPSS,
	SignatureAlgorithmSHA1WithRSA,
	SignatureAlgorithmNoneSHA1WithRSA,
	SignatureAlgorithmSHA1WithRSAPSS,
}

var EC_SIGNATURE_ALGORITHM = []SignatureAlgorithm{
	SignatureAlgorithmNoneWithECDSA,
	SignatureAlgorithmSHA1WithECDSA,
	SignatureAlgorithmSHA224WithECDSA,
	SignatureAlgorithmSHA256WithECDSA,
	SignatureAlgorithmDoubleSHA256WithECDSA,
	SignatureAlgorithmSHA384WithECDSA,
	SignatureAlgorithmSHA512WithECDSA,
	SignatureAlgorithmSHA3224WithECDSA,
	SignatureAlgorithmSHA3256WithECDSA,
	SignatureAlgorithmSHA3384WithECDSA,
	SignatureAlgorithmSHA3512WithECDSA,
	SignatureAlgorithmSHA256WithECDSADet,
	SignatureAlgorithmKECCAK224WithECDSA,
	SignatureAlgorithmKECCAK256WithECDSA,
	SignatureAlgorithmKECCAK384WithECDSA,
	SignatureAlgorithmKECCAK512WithECDSA,
}

var ED_SIGNATURE_ALGORITHM = []SignatureAlgorithm{
	SignatureAlgorithmEDDSA,
}

var DSA_SIGNATURE_ALGORITHM = []SignatureAlgorithm{
	SignatureAlgorithmNoneWithDSA,
	SignatureAlgorithmSHA224WithDSA,
	SignatureAlgorithmSHA256WithDSA,
	SignatureAlgorithmSHA384WithDSA,
	SignatureAlgorithmSHA512WithDSA,
	SignatureAlgorithmSHA1WithDSA,
}

var BLS_SIGNATURE_ALGORITHM = []SignatureAlgorithm{
	SignatureAlgorithmBLS,
}

// Function thats sends sign request to TSB
func (c *TSBClient) Sign(ctx context.Context, label string, password string, payload string, payloadType string, signatureAlgorithm SignatureAlgorithm, signatureType SignatureType) (*helpers.SignatureResponse, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	signatureType, err := normalizeSignatureType(signatureType)
	if err != nil {
		return nil, 500, err
	}
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"signRequest": {
		"payload": "` + payload + `",
		"payloadType": "` + payloadType + `",
		` + passwordString + `
		"signKeyName": "` + label + `",
		"signatureAlgorithm": "` + string(signatureAlgorithm) + `",
  		"signatureType":"` + string(signatureType) + `"

		}
	  }`)

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/synchronousSign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.SignatureResponse
	// response.KeyID = signKeyName
	// response.CertificateRequest = string(body)
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// Function thats sends asynchronous sign request to TSB
func (c *TSBClient) AsyncSign(ctx context.Context, label string, password string, payload string, payloadType string, signatureAlgorithm SignatureAlgorithm, signatureType SignatureType, customMetaData map[string]string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	signatureType, err := normalizeSignatureType(signatureType)
	if err != nil {
		return "", 500, err
	}
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	var additionalMetaDataInfo map[string]string = make(map[string]string)

	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Sign", additionalMetaDataInfo, customMetaData)
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
		"payload": "` + payload + `",
		"payloadType": "` + payloadType + `",
		` + passwordString + `
		"signKeyName": "` + label + `",
		"signatureAlgorithm": "` + string(signatureAlgorithm) + `",
		"signatureType": "` + string(signatureType) + `",
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `

	  }`
	var jsonStr = []byte(helpers.MinifyJson(`{
		"signRequest": ` + requestJson + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
	  }`))
	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/sign", bytes.NewBuffer(jsonStr))
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
	return result["signRequestId"].(string), code, nil

}

func normalizeSignatureType(signatureType SignatureType) (SignatureType, error) {
	if signatureType == "" {
		return SignatureTypeDER, nil
	}
	switch signatureType {
	case SignatureTypeDER, SignatureTypeETH, SignatureTypeRAW:
		return signatureType, nil
	default:
		return "", fmt.Errorf("unsupported signature type %q", signatureType)
	}
}

// Function thats sends verify request to TSB
func (c *TSBClient) Verify(ctx context.Context, label string, password string, payload string, signatureAlgorithm SignatureAlgorithm, signature string) (bool, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"masterKeyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"verifySignatureRequest": {
		  "payload": "` + payload + `",
		  ` + passwordString + `
		  "signKeyName": "` + label + `",
		  "signatureAlgorithm": "` + string(signatureAlgorithm) + `",
		  "signature": "` + signature + `"
		}
	  }`)

	req, err := http.NewRequestWithContext(ctx, "POST", c.HostURL+"/v1/verify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return false, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return false, code, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	if !helpers.ContainsKey(response, "signatureValid") {
		return false, 500, fmt.Errorf("error on verify response, need signatureValid, found %s", string(body[:]))
	}
	return response["signatureValid"].(bool), code, nil

}
