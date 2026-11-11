// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"net/http"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

type certificateRequest struct {
	SignKeyName                   string                        `json:"signKeyName"`
	KeyPassword                   []string                      `json:"keyPassword,omitempty"`
	SignatureAlgorithm            string                        `json:"signatureAlgorithm"`
	Validity                      int                           `json:"validity"`
	StandardCertificateAttributes helpers.CertificateAttributes `json:"standardCertificateAttributes"`
	KeyUsage                      []string                      `json:"keyUsage"`
	ExtendedKeyUsage              []string                      `json:"extendedKeyUsage"`
	MetaData                      *string                       `json:"metaData,omitempty"`
	MetaDataSignature             *signedMetaDataSignature      `json:"metaDataSignature,omitempty"`
}

type selfSignedCertificateRequest struct {
	SignKeyName          string                   `json:"signKeyName"`
	KeyPassword          []string                 `json:"keyPassword,omitempty"`
	SignatureAlgorithm   string                   `json:"signatureAlgorithm"`
	Validity             int                      `json:"validity"`
	CommonName           string                   `json:"commonName"`
	KeyUsage             []string                 `json:"keyUsage"`
	ExtendedKeyUsage     []string                 `json:"extendedKeyUsage"`
	MetaData             *string                  `json:"metaData,omitempty"`
	MetaDataSignature    *signedMetaDataSignature `json:"metaDataSignature,omitempty"`
	CertificateAuthority bool                     `json:"certificateAuthority"`
}

type signCertificateRequest struct {
	SignKeyName               string                   `json:"signKeyName"`
	KeyPassword               []string                 `json:"keyPassword,omitempty"`
	SignatureAlgorithm        string                   `json:"signatureAlgorithm"`
	CommonName                string                   `json:"commonName"`
	CertificateSigningRequest string                   `json:"certificateSigningRequest"`
	KeyUsage                  []string                 `json:"keyUsage"`
	ExtendedKeyUsage          []string                 `json:"extendedKeyUsage"`
	MetaData                  *string                  `json:"metaData,omitempty"`
	MetaDataSignature         *signedMetaDataSignature `json:"metaDataSignature,omitempty"`
	CertificateAuthority      bool                     `json:"certificateAuthority"`
}

type importCertificateRequest struct {
	Label       string `json:"label"`
	Certificate string `json:"certificate"`
}

// signedMetaDataSignature wraps the metadata signature of an asynchronous
// request. A nil signature is encoded as JSON null; the whole field is
// omitted for synchronous requests.
type signedMetaDataSignature struct {
	value *string
}

func (s signedMetaDataSignature) MarshalJSON() ([]byte, error) {
	return marshalJSON(s.value)
}

// prepareCertificateMetaData returns the metadata fields for an asynchronous
// certificate request.
func (c *TSBClient) prepareCertificateMetaData(requestType string, userMetaData map[string]string) (*string, *signedMetaDataSignature, error) {
	additionalMetaDataInfo := make(map[string]string, len(userMetaData))
	for index, value := range userMetaData {
		additionalMetaDataInfo[index] = value
	}
	metaDataB64, metaDataSignature, err := c.PrepareMetaData(requestType, additionalMetaDataInfo, map[string]string{})
	if err != nil {
		return nil, nil, err
	}
	return &metaDataB64, &signedMetaDataSignature{value: metaDataSignature}, nil
}

// Function thats create a certificate request to TSB
func (c *TSBClient) CreateCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, certAttributes helpers.CertificateAttributes, keyUsage []string, extendedKeyUsage []string) (*helpers.GenerateCertificateRequestResponse, int, error) {
	jsonStr, err := marshalJSON(certificateRequest{
		SignKeyName:                   signKeyName,
		KeyPassword:                   passwordChars(keyPassword),
		SignatureAlgorithm:            signatureAlgorithm,
		Validity:                      validity,
		StandardCertificateAttributes: certAttributes,
		KeyUsage:                      nonNilStrings(keyUsage),
		ExtendedKeyUsage:              nonNilStrings(extendedKeyUsage),
	})
	if err != nil {
		return nil, 500, err
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/synchronous/request", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.GenerateCertificateRequestResponse
	json.Unmarshal(body, &response)
	return &response, code, nil

}

func (c *TSBClient) CreateSelfSignedCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool) (*helpers.GenerateSelfSignedCertificateResponse, int, error) {
	jsonStr, err := marshalJSON(selfSignedCertificateRequest{
		SignKeyName:          signKeyName,
		KeyPassword:          passwordChars(keyPassword),
		SignatureAlgorithm:   signatureAlgorithm,
		Validity:             validity,
		CommonName:           commonName,
		KeyUsage:             nonNilStrings(keyUsage),
		ExtendedKeyUsage:     nonNilStrings(extendedKeyUsage),
		CertificateAuthority: certificateAuthority,
	})
	if err != nil {
		return nil, 500, err
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/synchronous/selfsign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.GenerateSelfSignedCertificateResponse
	json.Unmarshal(body, &response)
	return &response, code, nil

}

func (c *TSBClient) SignCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, certificateSigningRequest string, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool) (*helpers.GenerateSelfSignedCertificateResponse, int, error) {
	jsonStr, err := marshalJSON(signCertificateRequest{
		SignKeyName:               signKeyName,
		KeyPassword:               passwordChars(keyPassword),
		SignatureAlgorithm:        signatureAlgorithm,
		CommonName:                commonName,
		CertificateSigningRequest: certificateSigningRequest,
		KeyUsage:                  nonNilStrings(keyUsage),
		ExtendedKeyUsage:          nonNilStrings(extendedKeyUsage),
		CertificateAuthority:      certificateAuthority,
	})
	if err != nil {
		return nil, 500, err
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/synchronous/sign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.GenerateSelfSignedCertificateResponse
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// Function thats create a certificate request to TSB
func (c *TSBClient) AsyncCreateCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, certAttributes helpers.CertificateAttributes, keyUsage []string, extendedKeyUsage []string, userMetaData map[string]string) (string, int, error) {
	metaData, metaDataSignature, err := c.prepareCertificateMetaData("CertificateSigningRequest", userMetaData)
	if err != nil {
		return "", 500, err
	}
	jsonStr, err := c.signedRequestBody("csrSignRequest", certificateRequest{
		SignKeyName:                   signKeyName,
		KeyPassword:                   passwordChars(keyPassword),
		SignatureAlgorithm:            signatureAlgorithm,
		Validity:                      validity,
		StandardCertificateAttributes: certAttributes,
		KeyUsage:                      nonNilStrings(keyUsage),
		ExtendedKeyUsage:              nonNilStrings(extendedKeyUsage),
		MetaData:                      metaData,
		MetaDataSignature:             metaDataSignature,
	})
	if err != nil {
		return "", 500, err
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/request", bytes.NewBuffer(jsonStr))
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

func (c *TSBClient) AsyncSelfSignedCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool, userMetaData map[string]string) (string, int, error) {
	metaData, metaDataSignature, err := c.prepareCertificateMetaData("SelfSignCertificate", userMetaData)
	if err != nil {
		return "", 500, err
	}
	jsonStr, err := c.signedRequestBody("selfSignCertificateRequest", selfSignedCertificateRequest{
		SignKeyName:          signKeyName,
		KeyPassword:          passwordChars(keyPassword),
		SignatureAlgorithm:   signatureAlgorithm,
		Validity:             validity,
		CommonName:           commonName,
		KeyUsage:             nonNilStrings(keyUsage),
		ExtendedKeyUsage:     nonNilStrings(extendedKeyUsage),
		MetaData:             metaData,
		MetaDataSignature:    metaDataSignature,
		CertificateAuthority: certificateAuthority,
	})
	if err != nil {
		return "", 500, err
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/selfsign", bytes.NewBuffer(jsonStr))
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

func (c *TSBClient) AsyncSignCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, certificateSigningRequest string, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool, userMetaData map[string]string) (string, int, error) {
	metaData, metaDataSignature, err := c.prepareCertificateMetaData("Certificate", userMetaData)
	if err != nil {
		return "", 500, err
	}
	jsonStr, err := c.signedRequestBody("signCertificateRequest", signCertificateRequest{
		SignKeyName:               signKeyName,
		KeyPassword:               passwordChars(keyPassword),
		SignatureAlgorithm:        signatureAlgorithm,
		CommonName:                commonName,
		CertificateSigningRequest: certificateSigningRequest,
		KeyUsage:                  nonNilStrings(keyUsage),
		ExtendedKeyUsage:          nonNilStrings(extendedKeyUsage),
		MetaData:                  metaData,
		MetaDataSignature:         metaDataSignature,
		CertificateAuthority:      certificateAuthority,
	})
	if err != nil {
		return "", 500, err
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/sign", bytes.NewBuffer(jsonStr))
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

// Function thats import a certificate request from TSB
func (c *TSBClient) ImportCertificate(label string, certificate string) (*helpers.RequestResponseImportCertificate, int, error) {
	jsonStr, err := marshalJSON(importCertificateRequest{
		Label:       label,
		Certificate: certificate,
	})
	if err != nil {
		return nil, 500, err
	}

	req, err := http.NewRequest("POST", c.HostURL+"/v1/certificate/import/plain", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.RequestResponseImportCertificate
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// Function thats sends get request to TSB
func (c *TSBClient) GetCertificate(label string) (*helpers.RequestResponseCertificate, int, error) {
	req, err := http.NewRequest("GET", c.HostURL+"/v1/certificate/"+label, bytes.NewBuffer(nil))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var requestResponse helpers.RequestResponseCertificate
	errJSON := json.Unmarshal(body, &requestResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}

	return &requestResponse, code, nil
}

// Function thats delete certificate TSB
func (c *TSBClient) DeleteCertificate(label string) (int, error) {
	req, err := http.NewRequest("DELETE", c.HostURL+"/v1/certificate/"+label, nil)
	if err != nil {
		return 500, err
	}
	_, code, errReq := c.doRequest(req, KeyOperationTokenName)
	if errReq != nil {
		return code, errReq
	}
	return code, nil
}
