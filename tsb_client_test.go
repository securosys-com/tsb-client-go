// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
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
