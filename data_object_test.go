// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	helpers "github.com/securosys-com/tsb-client-go/helpers"
)

func TestCreateDataObject(t *testing.T) {
	modifiable := false
	destroyable := true
	private := true
	dataObjectType := "SecretData"

	want := helpers.DataObject{
		Name:  "test/object",
		Value: "c2VjcmV0",
		Attributes: &helpers.DataObjectAttributes{
			Modifiable:  &modifiable,
			Destroyable: &destroyable,
			Private:     &private,
		},
		KMIP: &helpers.DataObjectKMIP{DataObjectType: &dataObjectType},
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != dataObjectPath {
			t.Fatalf("path = %q, want %q", request.URL.Path, dataObjectPath)
		}
		if request.Header.Get("X-API-KEY") != "management-token" {
			t.Fatalf("X-API-KEY = %q, want management-token", request.Header.Get("X-API-KEY"))
		}

		var got helpers.DataObject
		if err := json.NewDecoder(request.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Name != want.Name || got.Value != want.Value {
			t.Fatalf("data object = %#v, want %#v", got, want)
		}
		if got.Attributes == nil || got.Attributes.Modifiable == nil || *got.Attributes.Modifiable {
			t.Fatalf("explicit modifiable=false was not preserved: %#v", got.Attributes)
		}
		if got.KMIP == nil || got.KMIP.DataObjectType == nil || *got.KMIP.DataObjectType != dataObjectType {
			t.Fatalf("KMIP data = %#v", got.KMIP)
		}
		writer.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := newDataObjectTestClient(t, server.URL)
	code, err := client.CreateDataObject(context.Background(), want)
	requireNoError(t, err)
	if code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", code, http.StatusCreated)
	}
}

func TestGetDataObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", request.Method)
		}
		if request.URL.EscapedPath() != dataObjectPath+"/test%2Fobject" {
			t.Fatalf("escaped path = %q", request.URL.EscapedPath())
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"name":"test/object","value":"c2VjcmV0","attributes":{"destroyable":true}}`))
	}))
	defer server.Close()

	client := newDataObjectTestClient(t, server.URL)
	got, code, err := client.GetDataObject(nil, "test/object")
	requireNoError(t, err)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want %d", code, http.StatusOK)
	}
	if got.Name != "test/object" || got.Value != "c2VjcmV0" {
		t.Fatalf("data object = %#v", got)
	}
	if got.Attributes == nil || got.Attributes.Destroyable == nil || !*got.Attributes.Destroyable {
		t.Fatalf("attributes = %#v", got.Attributes)
	}
}

func TestDeleteDataObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete {
			t.Fatalf("method = %s, want DELETE", request.Method)
		}
		if request.URL.EscapedPath() != dataObjectPath+"/object%20name" {
			t.Fatalf("escaped path = %q", request.URL.EscapedPath())
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newDataObjectTestClient(t, server.URL)
	code, err := client.DeleteDataObject(context.Background(), "object name")
	requireNoError(t, err)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestGetDataObjectReturnsInvalidJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("not-json"))
	}))
	defer server.Close()

	client := newDataObjectTestClient(t, server.URL)
	dataObject, code, err := client.GetDataObject(context.Background(), "object")
	if err == nil {
		t.Fatal("expected JSON decoding error")
	}
	if dataObject != nil || code != http.StatusOK {
		t.Fatalf("data object = %#v, status = %d", dataObject, code)
	}
}

func newDataObjectTestClient(t *testing.T, hostURL string) *TSBClient {
	t.Helper()
	client, err := NewTSBClient(hostURL, AuthStruct{
		AuthType: authTypeNone,
		ApiKeys: ApiKeyTypes{
			KeyManagementToken: []string{"management-token"},
		},
	})
	requireNoError(t, err)
	return client
}
