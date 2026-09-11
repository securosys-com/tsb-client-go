// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"time"

	"github.com/securosys-com/tsb-client-go/helpers"
)

const defaultApprovalPollInterval = 5 * time.Second

// WaitForRequest polls an asynchronous request until it reaches a terminal
// state or ctx is cancelled. PENDING and APPROVED are non-terminal states.
func (c *TSBClient) WaitForRequest(ctx context.Context, requestID string) (*helpers.RequestResponse, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if requestID == "" {
		return nil, 0, fmt.Errorf("request id is required")
	}

	pollInterval := c.ApprovalPollInterval
	if pollInterval <= 0 {
		pollInterval = defaultApprovalPollInterval
	}

	waitStarted := time.Now()
	if c.Logger != nil {
		if deadline, ok := ctx.Deadline(); ok {
			c.Logger.Info("Waiting for approvals", "request_id", requestID, "poll_interval", pollInterval.String(), "timeout_in", time.Until(deadline).Round(time.Second).String())
		} else {
			c.Logger.Info("Waiting for approvals", "request_id", requestID, "poll_interval", pollInterval.String())
		}
	}

	for {
		request, code, err := c.GetRequest(ctx, requestID)
		if err != nil {
			return nil, code, err
		}
		if request.Status != "PENDING" && request.Status != "APPROVED" {
			if c.Logger != nil {
				c.Logger.Info("Securosys approval request completed", "request_id", requestID, "status", request.Status, "elapsed", time.Since(waitStarted).Round(time.Second).String())
			}
			return request, code, nil
		}
		if c.Logger != nil {
			c.Logger.Debug("Securosys approval request still pending", "request_id", requestID, "status", request.Status, "elapsed", time.Since(waitStarted).Round(time.Second).String(), "approved_by", request.ApprovedBy, "not_yet_approved_by", request.NotYetApprovedBy, "rejected_by", request.RejectedBy)
		}

		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			stopErr := ctx.Err()
			if stopErr == nil {
				stopErr = context.Canceled
			}
			if c.Logger != nil {
				c.Logger.Warn("Securosys approval request wait stopped", "request_id", requestID, "elapsed", time.Since(waitStarted).Round(time.Second).String(), "error", stopErr)
			}
			if !timer.Stop() {
				<-timer.C
			}
			return nil, 0, stopErr
		case <-timer.C:
		}
	}
}
