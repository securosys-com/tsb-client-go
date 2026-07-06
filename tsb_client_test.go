// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

const (
	testAppName = "Securosys Client Test"
	testTSBURL  = "https://tsb.example.test/"

	authTypeNone  = "NONE"
	authTypeToken = "TOKEN"
	authTypeCert  = "CERT"

	envTSBURL                     = "TSB_URL"
	envBearerToken                = "TSB_BEARER_TOKEN"
	envCertPEM                    = "TSB_CERT_PEM"
	envKeyPEM                     = "TSB_KEY_PEM"
	envCertPath                   = "TSB_CERT_PATH"
	envKeyPath                    = "TSB_KEY_PATH"
	envKeyManagementToken         = "TSB_KEY_MANAGEMENT_TOKEN"
	envKeyOperationToken          = "TSB_KEY_OPERATION_TOKEN"
	envApproverToken              = "TSB_APPROVER_TOKEN"
	envServiceToken               = "TSB_SERVICE_TOKEN"
	envApproverKeyManagementToken = "TSB_APPROVER_KEY_MANAGEMENT_TOKEN"
)

func TestNewTSBClientTrimsTrailingSlash(t *testing.T) {
	tsbClient, err := NewTSBClient(testTSBURL, AuthStruct{
		AuthType: authTypeNone,
		AppName:  testAppName,
	})
	requireNoError(t, err)

	if tsbClient.HostURL != "https://tsb.example.test" {
		t.Fatalf("HostURL = %q, want trailing slash trimmed", tsbClient.HostURL)
	}
}

func TestNewClientUsesSnakeCaseConfigParameters(t *testing.T) {
	privateKey := "private"
	publicKey := "public"
	config := &helpers.SecurosysConfig{
		Auth:               authTypeToken,
		BearerToken:        "bearer-token",
		CertPath:           "/tmp/client.crt",
		KeyPath:            "/tmp/client.key",
		RestApi:            testTSBURL,
		AppName:            testAppName,
		ApplicationKeyPair: `{"private_key":"` + privateKey + `","public_key":"` + publicKey + `"}`,
		ApiKeys:            `{"key_management_token":["management"],"key_operation_token":["operation"],"service_token":["service"]}`,
	}

	bytes, err := json.Marshal(config)
	requireNoError(t, err)
	jsonConfig := string(bytes)
	for _, parameter := range []string{"bearer_token", "cert_path", "key_path", "rest_api", "app_name", "application_key_pair", "api_keys"} {
		if !strings.Contains(jsonConfig, `"`+parameter+`"`) {
			t.Fatalf("marshaled config missing snake_case parameter %q in %s", parameter, jsonConfig)
		}
	}
	for _, parameter := range []string{"bearertoken", "certpath", "keypath", "restapi", "appName", "applicationKeyPair", "apiKeys"} {
		if strings.Contains(jsonConfig, `"`+parameter+`"`) {
			t.Fatalf("marshaled config contains non-snake-case parameter %q in %s", parameter, jsonConfig)
		}
	}

	securosysClient, err := NewClient(config)
	requireNoError(t, err)

	if securosysClient.HostURL != "https://tsb.example.test" {
		t.Fatalf("HostURL = %q, want trailing slash trimmed", securosysClient.HostURL)
	}
	if securosysClient.Auth.BearerToken != "bearer-token" {
		t.Fatalf("BearerToken = %q, want bearer-token", securosysClient.Auth.BearerToken)
	}
	if securosysClient.Auth.CertPath != "/tmp/client.crt" {
		t.Fatalf("CertPath = %q, want /tmp/client.crt", securosysClient.Auth.CertPath)
	}
	if securosysClient.Auth.KeyPath != "/tmp/client.key" {
		t.Fatalf("KeyPath = %q, want /tmp/client.key", securosysClient.Auth.KeyPath)
	}
	if securosysClient.Auth.ApplicationKeyPair.PrivateKey == nil || *securosysClient.Auth.ApplicationKeyPair.PrivateKey != privateKey {
		t.Fatalf("PrivateKey = %v, want %q", securosysClient.Auth.ApplicationKeyPair.PrivateKey, privateKey)
	}
	if securosysClient.Auth.ApplicationKeyPair.PublicKey == nil || *securosysClient.Auth.ApplicationKeyPair.PublicKey != publicKey {
		t.Fatalf("PublicKey = %v, want %q", securosysClient.Auth.ApplicationKeyPair.PublicKey, publicKey)
	}
	if got := securosysClient.Auth.ApiKeys.KeyManagementToken; len(got) != 1 || got[0] != "management" {
		t.Fatalf("KeyManagementToken = %v, want [management]", got)
	}
	if got := securosysClient.Auth.ApiKeys.KeyOperationToken; len(got) != 1 || got[0] != "operation" {
		t.Fatalf("KeyOperationToken = %v, want [operation]", got)
	}
	if got := securosysClient.Auth.ApiKeys.ServiceToken; len(got) != 1 || got[0] != "service" {
		t.Fatalf("ServiceToken = %v, want [service]", got)
	}
}

func TestNoAuthWithTSB(t *testing.T) {
	skipMissingEnv(t, envTSBURL)
	skipIfAuthEnvEnabled(t)

	tsbClient := newTestTSBClient(t, AuthStruct{
		AuthType: authTypeNone,
		AppName:  testAppName,
	})

	checkTSBConnection(t, tsbClient)
}

func TestBearerTokenWithTSB(t *testing.T) {
	skipMissingEnv(t, envTSBURL, envBearerToken)

	tsbClient := newTestTSBClient(t, AuthStruct{
		AuthType:    authTypeToken,
		BearerToken: envRequired(t, envBearerToken),
		AppName:     testAppName,
		ApiKeys:     testAPIKeysFromEnv(),
	})

	checkTSBConnection(t, tsbClient)
}

func TestCertificateVariablesWithTSB(t *testing.T) {
	skipMissingEnv(t, envTSBURL, envCertPEM, envKeyPEM)

	tsbClient := newTestTSBClient(t, AuthStruct{
		AuthType: authTypeCert,
		CertPEM:  envRequired(t, envCertPEM),
		KeyPEM:   envRequired(t, envKeyPEM),
		AppName:  testAppName,
		ApiKeys:  testAPIKeysFromEnv(),
	})

	checkTSBConnection(t, tsbClient)
}

func TestCertificateFilesWithTSB(t *testing.T) {
	skipMissingEnv(t, envTSBURL, envCertPath, envKeyPath)
	skipIfEnvSet(t, envBearerToken)
	if certVariablesEnabled() {
		t.Skipf("set %s/%s, skipping certificate file auth test", envCertPEM, envKeyPEM)
	}

	tsbClient := newTestTSBClient(t, AuthStruct{
		AuthType: authTypeCert,
		CertPath: envRequired(t, envCertPath),
		KeyPath:  envRequired(t, envKeyPath),
		AppName:  testAppName,
		ApiKeys:  testAPIKeysFromEnv(),
	})

	checkTSBConnection(t, tsbClient)
}

func TestTSBClientFromEnvWithTSB(t *testing.T) {
	tsbClient := newTestTSBClientFromEnv(t)

	checkTSBConnection(t, tsbClient)
}

func newTestTSBClientFromEnv(t *testing.T) *TSBClient {
	t.Helper()
	skipMissingEnv(t, envTSBURL)

	auth := AuthStruct{
		AuthType: authTypeNone,
		AppName:  testAppName,
		ApiKeys:  testAPIKeysFromEnv(),
	}

	if os.Getenv(envBearerToken) != "" {
		auth.AuthType = authTypeToken
		auth.BearerToken = envRequired(t, envBearerToken)
		return newTestTSBClient(t, auth)
	}

	if certVariablesEnabled() {
		auth.AuthType = authTypeCert
		auth.CertPEM = envRequired(t, envCertPEM)
		auth.KeyPEM = envRequired(t, envKeyPEM)
		return newTestTSBClient(t, auth)
	}

	if certFilesEnabled() {
		auth.AuthType = authTypeCert
		auth.CertPath = envRequired(t, envCertPath)
		auth.KeyPath = envRequired(t, envKeyPath)
		return newTestTSBClient(t, auth)
	}

	return newTestTSBClient(t, auth)
}

func newTestTSBClient(t *testing.T, auth AuthStruct) *TSBClient {
	t.Helper()

	tsbClient, err := NewTSBClient(envRequired(t, envTSBURL), auth)
	requireNoError(t, err)
	return tsbClient
}

func checkTSBConnection(t *testing.T, tsbClient *TSBClient) {
	t.Helper()

	_, _, err := tsbClient.CheckConnection(context.Background())
	requireNoError(t, err)
}

func testAPIKeysFromEnv() ApiKeyTypes {
	return ApiKeyTypes{
		KeyManagementToken:         envList(envKeyManagementToken),
		KeyOperationToken:          envList(envKeyOperationToken),
		ApproverToken:              envList(envApproverToken),
		ServiceToken:               envList(envServiceToken),
		ApproverKeyManagementToken: envList(envApproverKeyManagementToken),
	}
}

func envList(name string) []string {
	value := os.Getenv(name)
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func skipMissingEnv(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if os.Getenv(name) == "" {
			t.Skipf("set %s to run this TSB test", name)
		}
	}
}

func skipIfAuthEnvEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv(envBearerToken) != "" {
		t.Skipf("set %s, skipping no-auth test", envBearerToken)
	}
	if certVariablesEnabled() {
		t.Skipf("set %s/%s, skipping no-auth test", envCertPEM, envKeyPEM)
	}
	if certFilesEnabled() {
		t.Skipf("set %s/%s, skipping no-auth test", envCertPath, envKeyPath)
	}
}

func skipIfEnvSet(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if os.Getenv(name) != "" {
			t.Skipf("set %s, skipping this TSB test", name)
		}
	}
}

func certVariablesEnabled() bool {
	return os.Getenv(envCertPEM) != "" && os.Getenv(envKeyPEM) != ""
}

func certFilesEnabled() bool {
	return os.Getenv(envCertPath) != "" && os.Getenv(envKeyPath) != ""
}

func envRequired(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func envDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func envFloatDefault(name string, fallback float64) float64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	result, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return result
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
