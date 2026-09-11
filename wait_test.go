// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForRequestReturnsTerminalRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/request/request-id" {
			t.Fatalf("request path = %q", r.URL.Path)
		}
		status := "PENDING"
		result := ""
		if calls.Add(1) == 2 {
			status = "EXECUTED"
			result = "plaintext"
		}
		_, _ = fmt.Fprintf(w, `{"id":"request-id","status":%q,"result":%q}`, status, result)
	}))
	defer server.Close()

	client, err := NewTSBClient(server.URL, AuthStruct{AuthType: "NONE"})
	if err != nil {
		t.Fatal(err)
	}
	client.ApprovalPollInterval = time.Millisecond

	request, code, err := client.WaitForRequest(t.Context(), "request-id")
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK || request.Status != "EXECUTED" || request.Result != "plaintext" {
		t.Fatalf("WaitForRequest() = %#v, %d, want executed request", request, code)
	}
}

func TestWaitForRequestHonorsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"id":"request-id","status":"PENDING"}`)
	}))
	defer server.Close()

	client, err := NewTSBClient(server.URL, AuthStruct{AuthType: "NONE"})
	if err != nil {
		t.Fatal(err)
	}
	client.ApprovalPollInterval = time.Hour

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := client.WaitForRequest(ctx, "request-id"); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForRequest() error = %v, want context.Canceled", err)
	}
}
