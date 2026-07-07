// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"encoding/json"
)

// STRUCTS

// Structure for all asychnronous operations
type RequestResponse struct {
	Id               string   `json:"id"`
	Status           string   `json:"status"`
	ExecutionTime    string   `json:"executionTime"`
	ApprovedBy       []string `json:"approvedBy"`
	NotYetApprovedBy []string `json:"notYetApprovedBy"`
	RejectedBy       []string `json:"rejectedBy"`
	Result           string   `json:"result"`
}

// Structure for get key attributes response
type KeyAttributes struct {
	Id                 *string
	Label              string
	Attributes         map[string]bool
	KeySize            float64
	Policy             *Policy
	DerivedAttributes  map[string]interface{}
	PublicKey          string
	Algorithm          string
	AlgorithmOid       string
	CurveOid           string
	Version            string
	Active             bool
	Xml                string
	XmlSignature       string
	AttestationKeyName string
}

// SecurosysConfig includes the minimum configuration
// required to instantiate a new Securosys TSB client.
type SecurosysConfig struct {
	Auth               string `json:"auth" mapstructure:"auth"`
	BearerToken        string `json:"bearer_token" mapstructure:"bearer_token"`
	CertPath           string `json:"cert_path" mapstructure:"cert_path"`
	KeyPath            string `json:"key_path" mapstructure:"key_path"`
	RestApi            string `json:"rest_api" mapstructure:"rest_api"`
	AppName            string `json:"app_name" mapstructure:"app_name"`
	ApplicationKeyPair string `json:"application_key_pair" mapstructure:"application_key_pair"`
	ApiKeys            string `json:"api_keys" mapstructure:"api_keys"`
}

// Structure for certificate operations
type RequestResponseCertificate struct {
	Label       string `json:"label"`
	Certificate string `json:"certificate"`
}

// Structure for certificate operations
type RequestResponseImportCertificate struct {
	Label       string `json:"label"`
	Certificate string `json:"certificate"`
}

type GenerateCertificateRequest struct {
	// The same key id as passed in the request.
	KeyID        string            `json:"keyId"`
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
	Certificate  Certificate       `json:"certificate"`
}

type CertificateAttributes struct {
	CommonName           string  `json:"commonName"`
	Country              *string `json:"country"`
	StateOrProvinceName  *string `json:"stateOrProvinceName"`
	Locality             *string `json:"locality"`
	OrganizationName     *string `json:"organizationName"`
	OrganizationUnitName *string `json:"organizationUnitName"`
	Email                *string `json:"email"`
	Title                *string `json:"title"`
	Surname              *string `json:"surname"`
	GivenName            *string `json:"givenName"`
	Initials             *string `json:"initials"`
	Pseudonym            *string `json:"pseudonym"`
	GenerationQualifier  *string `json:"generationQualifier"`
}

func (ca *CertificateAttributes) ToString() string {
	respData := map[string]interface{}{
		"commonName":       ca.CommonName,
		"country":          ca.Country,
		"organizationName": ca.OrganizationName,
	}
	jsonStr, _ := json.Marshal(respData)
	return string(jsonStr[:])
}

type Certificate struct {
	Validity   int                   `json:"validity"`
	Attributes CertificateAttributes `json:"attributes"`
}

type ImportCertificateRequest struct {
	// The same key id as passed in the request.
	KeyID        string            `json:"keyId"`
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
}

type GenerateCertificateResponse struct {
	// The same key id as passed in the request.
	KeyID       string `json:"label"`
	Certificate string `json:"certificate"`
	KeyVersion  string `json:"keyVersion"`
}

type GenerateCertificateRequestResponse struct {
	// The same key id as passed in the request.
	KeyID              string `json:"label"`
	CertificateRequest string `json:"certificateSigningRequest"`
	KeyVersion         string `json:"keyVersion"`
}

type GenerateSelfSignedCertificateResponse struct {
	// The same key id as passed in the request.
	KeyID      string `json:"label"`
	KeyVersion string `json:"keyVersion"`

	CertificateRequest string `json:"certificate"`
}
type DecryptResponse struct {
	Payload string `json:"payload"`
}
type EncryptResponse struct {
	EncryptedPayload                                 string  `json:"encryptedPayload"`
	EncryptedPayloadWithoutMessageAuthenticationCode string  `json:"encryptedPayloadWithoutMessageAuthenticationCode"`
	InitializationVector                             *string `json:"initializationVector"`
	MessageAuthenticationCode                        *string `json:"messageAuthenticationCode"`
	KeyVersion                                       string  `json:"keyVersion"`
}

type SignatureResponse struct {
	Signature  string `json:"signature"`
	KeyVersion string `json:"keyVersion"`
}
type WrapResponse struct {
	WrappedKey string `json:"wrappedKey"`
	KeyVersion string `json:"keyVersion"`
}
type RandomResponse struct {
	Random string `json:"random"`
}

type Approval struct {
	TypeOfKey string  `json:"type"`
	Name      *string `json:"name"`
	Value     *string `json:"value"`
}
type Group struct {
	Name      string     `json:"name"`
	Quorum    int        `json:"quorum"`
	Approvals []Approval `json:"approvals"`
}
type Token struct {
	Name     string  `json:"name"`
	Timelock int     `json:"timelock"`
	Timeout  int     `json:"timeout"`
	Groups   []Group `json:"groups"`
}
type Rule struct {
	Tokens []Token `json:"tokens"`
}
type KeyStatus struct {
	Blocked bool `json:"blocked"`
}

// Policy structure for rules use, block, unblock, modify
type Policy struct {
	RuleUse     Rule       `json:"ruleUse"`
	RuleBlock   *Rule      `json:"ruleBlock,omitempty"`
	RuleUnBlock *Rule      `json:"ruleUnblock,omitempty"`
	RuleModify  *Rule      `json:"ruleModify,omitempty"`
	KeyStatus   *KeyStatus `json:"keyStatus,omitempty"`
}

//END STRUCTS
