// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// HostURL - Default Securosys TSB URL
const HostURL string = ""

// TSBClient struct
type TSBClient struct {
	HostURL              string
	HTTPClient           *http.Client
	Auth                 AuthStruct
	Logger               Logger
	ApprovalPollInterval time.Duration
}

type Logger interface {
	Info(message string, args ...interface{})
	Debug(message string, args ...interface{})
	Warn(message string, args ...interface{})
}
type AuthStruct struct {
	AppName                string      `json:"app_name" mapstructure:"app_name"`
	AuthType               string      `json:"auth" mapstructure:"auth"`
	CertPath               string      `json:"cert_path" mapstructure:"cert_path"`
	KeyPath                string      `json:"key_path" mapstructure:"key_path"`
	CertPEM                string      `json:"cert_pem,omitempty" mapstructure:"cert_pem"`
	KeyPEM                 string      `json:"key_pem,omitempty" mapstructure:"key_pem"`
	BearerToken            string      `json:"bearer_token" mapstructure:"bearer_token"`
	ApiKeys                ApiKeyTypes `json:"api_keys" mapstructure:"api_keys"`
	ApplicationKeyPair     KeyPair     `json:"application_key_pair" mapstructure:"application_key_pair"`
	CurrentApiKeyTypeIndex ApiKeyTypesRetry
}
type KeyPair struct {
	PrivateKey *string `json:"private_key,omitempty" mapstructure:"private_key"`
	PublicKey  *string `json:"public_key,omitempty" mapstructure:"public_key"`
}

type ApiKeyTypes struct {
	KeyManagementToken         []string `json:"key_management_token,omitempty" mapstructure:"key_management_token"`
	KeyOperationToken          []string `json:"key_operation_token,omitempty" mapstructure:"key_operation_token"`
	ApproverToken              []string `json:"approver_token,omitempty" mapstructure:"approver_token"`
	ServiceToken               []string `json:"service_token,omitempty" mapstructure:"service_token"`
	ApproverKeyManagementToken []string `json:"approver_key_management_token,omitempty" mapstructure:"approver_key_management_token"`
}
type ApiKeyTypesRetry struct {
	KeyManagementTokenIndex         int `json:"key_management_token_index" mapstructure:"key_management_token_index"`
	KeyOperationTokenIndex          int `json:"key_operation_token_index" mapstructure:"key_operation_token_index"`
	ApproverTokenIndex              int `json:"approver_token_index" mapstructure:"approver_token_index"`
	ServiceTokenIndex               int `json:"service_token_index" mapstructure:"service_token_index"`
	ApproverKeyManagementTokenIndex int `json:"approver_key_management_token_index" mapstructure:"approver_key_management_token_index"`
}

const (
	KeyManagementTokenName         = "KeyManagementToken"
	KeyOperationTokenName          = "KeyOperationToken"
	ApproverTokenName              = "ApproverToken"
	ServiceTokenName               = "ServiceToken"
	ApproverKeyManagementTokenName = "ApproverKeyManagementToken"
)

// Function inicialize new client for accessing TSB
func NewTSBClient(restApi string, settings AuthStruct) (*TSBClient, error) {
	restApi = strings.TrimSuffix(restApi, "/")
	c := TSBClient{
		HTTPClient: &http.Client{Timeout: 9999999 * time.Second},
		HostURL:    restApi,
		Auth:       settings,
	}

	return &c, nil
}

func (a *TSBClient) RollOverApiKey(name string) error {
	switch name {
	case KeyManagementTokenName:
		a.Auth.CurrentApiKeyTypeIndex.KeyManagementTokenIndex += 1
		return nil
	case KeyOperationTokenName:
		if len(a.Auth.ApiKeys.KeyOperationToken) == 0 {
			return fmt.Errorf("no KeyOperationToken provided")
		}
		a.Auth.CurrentApiKeyTypeIndex.KeyOperationTokenIndex += 1
		return nil
	case ApproverTokenName:
		if len(a.Auth.ApiKeys.ApproverToken) == 0 {
			return fmt.Errorf("no ApproverToken provided")
		}
		a.Auth.CurrentApiKeyTypeIndex.ApproverTokenIndex += 1
		return nil
	case ServiceTokenName:
		if len(a.Auth.ApiKeys.ServiceToken) == 0 {
			return fmt.Errorf("no ServiceToken provided")
		}
		a.Auth.CurrentApiKeyTypeIndex.ServiceTokenIndex += 1
		return nil
	case ApproverKeyManagementTokenName:
		if len(a.Auth.ApiKeys.ApproverKeyManagementToken) == 0 {
			return fmt.Errorf("no ApproverKeyManagementToken provided")
		}
		a.Auth.CurrentApiKeyTypeIndex.ApproverKeyManagementTokenIndex += 1
		return nil
	default:
		return fmt.Errorf("no api keys exists for name=%s", name)
	}
}

var ErrNoApiKeysConfigured = errors.New("no api key configured")
var ErrNoApiKeysRemaining = errors.New("no api keys remaining (all failed)")

func (a *TSBClient) GetApiKeyByName(name string) (string, error) {
	var selectedIdx int
	var selectedMap []string

	switch name {
	case KeyManagementTokenName:
		selectedIdx = a.Auth.CurrentApiKeyTypeIndex.KeyManagementTokenIndex
		selectedMap = a.Auth.ApiKeys.KeyManagementToken
	case KeyOperationTokenName:
		selectedIdx = a.Auth.CurrentApiKeyTypeIndex.KeyOperationTokenIndex
		selectedMap = a.Auth.ApiKeys.KeyOperationToken
	case ApproverTokenName:
		selectedIdx = a.Auth.CurrentApiKeyTypeIndex.ApproverTokenIndex
		selectedMap = a.Auth.ApiKeys.ApproverToken
	case ServiceTokenName:
		selectedIdx = a.Auth.CurrentApiKeyTypeIndex.ServiceTokenIndex
		selectedMap = a.Auth.ApiKeys.ServiceToken
	case ApproverKeyManagementTokenName:
		selectedIdx = a.Auth.CurrentApiKeyTypeIndex.ApproverKeyManagementTokenIndex
		selectedMap = a.Auth.ApiKeys.ApproverKeyManagementToken
	default:
		return "", fmt.Errorf("no api keys exists for name=%s", name)
	}

	if len(selectedMap) == 0 {
		return "", ErrNoApiKeysConfigured
	}
	if len(selectedMap) > selectedIdx {
		return selectedMap[selectedIdx], nil
	}
	return "", ErrNoApiKeysRemaining
}

// Function that making all requests. Using config for Authorization to TSB
func (c *TSBClient) doRequest(req *http.Request, apiKeyName string) ([]byte, int, error) {
	if c.Auth.AuthType == "TOKEN" {
		req.Header.Set("Authorization", "Bearer "+c.Auth.BearerToken)
	}

	if c.Auth.AuthType == "CERT" {
		caCert := []byte(c.Auth.CertPEM)
		if len(caCert) == 0 {
			var err error
			caCert, err = os.ReadFile(c.Auth.CertPath)
			if err != nil {
				return nil, 0, err
			}
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		var clientTLSCert tls.Certificate
		var err error
		if c.Auth.CertPEM != "" || c.Auth.KeyPEM != "" {
			clientTLSCert, err = tls.X509KeyPair([]byte(c.Auth.CertPEM), []byte(c.Auth.KeyPEM))
		} else {
			clientTLSCert, err = tls.LoadX509KeyPair(c.Auth.CertPath, c.Auth.KeyPath)
		}
		if err != nil {
			return nil, 0, err
		}

		c.HTTPClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{clientTLSCert},
			},
		}
	}

	apiKey, err := c.GetApiKeyByName(apiKeyName)
	if err != nil && err != ErrNoApiKeysConfigured {
		return []byte(fmt.Sprintf("All apikeys in group %s are invalid", apiKeyName)), 401, fmt.Errorf("status: %d, body: All apikeys in group %s are invalid", 401, apiKeyName)
	}
	if apiKey != "" {
		req.Header.Set("X-API-KEY", apiKey)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	// make nilaway happy
	if res == nil {
		return nil, 0, err
	}
	if err != nil {
		return nil, res.StatusCode, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, res.StatusCode, err
	}

	if apiKey != "" && res.StatusCode == http.StatusUnauthorized {
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		errorCode := result["errorCode"].(float64)

		if errorCode == 631 {
			c.RollOverApiKey(apiKeyName)
			return c.doRequest(req, apiKeyName)
		}
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return body, res.StatusCode, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}

	return body, res.StatusCode, err
}

func (c *TSBClient) GetApplicationPrivateKey() *rsa.PrivateKey {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil {
		return nil
	}

	block, _ := pem.Decode(c.WrapPrivateKeyWithHeaders(false))
	if block == nil {
		return nil
	}

	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	if key == nil {
		block, _ = pem.Decode(c.WrapPrivateKeyWithHeaders(true))
		if block == nil {
			return nil
		}

		parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}

		key := parseResult.(*rsa.PrivateKey)
		return key
	}
	return key
}

func (c *TSBClient) WrapPrivateKeyWithHeaders(pkcs8 bool) []byte {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil {
		return nil
	}

	if pkcs8 {
		return []byte("-----BEGIN PRIVATE KEY-----\n" + *c.Auth.ApplicationKeyPair.PrivateKey + "\n-----END PRIVATE KEY-----")
	} else {
		return []byte("-----BEGIN RSA PRIVATE KEY-----\n" + *c.Auth.ApplicationKeyPair.PrivateKey + "\n-----END RSA PRIVATE KEY-----")
	}
}

func (c *TSBClient) GenerateRequestSignature(requestData string) []byte {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil || c.Auth.ApplicationKeyPair.PublicKey == nil {
		return []byte("null")
	}
	dst := &bytes.Buffer{}
	if err := json.Compact(dst, []byte(requestData)); err != nil {
		// TODO: Propagate error. Requires updating all users of this function.
		panic(err)
	}

	signature, err := c.SignData(dst.Bytes())
	if err != nil {
		// TODO: Propagate error
		panic(err)
	}

	return []byte(`{
		"signature": "` + *signature + `",
		"digestAlgorithm": "SHA-256",
		"publicKey": "` + *c.Auth.ApplicationKeyPair.PublicKey + `"
		}
	`)
}

func (c *TSBClient) SignData(dataToSign []byte) (*string, error) {
	if c.Auth.ApplicationKeyPair.PrivateKey == nil || c.Auth.ApplicationKeyPair.PublicKey == nil {
		return nil, fmt.Errorf("no Application Private Key or Public Key provided")
	}
	h := sha256.New()
	h.Write(dataToSign)
	bs := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.GetApplicationPrivateKey(), crypto.SHA256, bs)
	if err != nil {
		return nil, err
	}
	result := b64.StdEncoding.EncodeToString(signature)
	return &result, nil
}

// Function preparing MetaData, which We are send with all asynchronous requests
func (c *TSBClient) PrepareMetaData(requestType string, additionalMetaData map[string]string, customMetaData map[string]string) (string, *string, error) {
	now := time.Now().UTC()
	var metaData map[string]string = make(map[string]string)
	metaData["time"] = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
	metaData["app"] = c.Auth.AppName
	metaData["type"] = requestType
	for key, value := range additionalMetaData {
		metaData[key] = value
	}
	for key, value := range customMetaData {
		metaData[key] = value
	}
	metaJsonStr, errMarshal := json.Marshal(metaData)
	if errMarshal != nil {
		return "", nil, errMarshal
	}
	result, err := c.SignData(metaJsonStr)
	if err != nil {
		return b64.StdEncoding.EncodeToString(metaJsonStr),
			nil, nil

	}
	return b64.StdEncoding.EncodeToString(metaJsonStr),
		result, nil
}
