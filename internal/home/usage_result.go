package home

import (
	"context"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// RecordUsagePayload applies downstream usage status to the scheduler auth state.
func (r *Runtime) RecordUsagePayload(ctx context.Context, payload string) {
	// Validate input data before converting it into runtime state.
	if r == nil || r.coreManager == nil {
		return
	}
	payload = strings.TrimSpace(payload)
	if payload == "" || !gjson.Valid(payload) {
		return
	}

	authIndex := strings.TrimSpace(gjson.Get(payload, "auth_index").String())
	if authIndex == "" {
		return
	}

	provider := strings.TrimSpace(gjson.Get(payload, "provider").String())
	model := strings.TrimSpace(gjson.Get(payload, "model").String())
	if model == "" {
		model = strings.TrimSpace(gjson.Get(payload, "alias").String())
	}

	statusCode := int(gjson.Get(payload, "fail.status_code").Int())
	failed := gjson.Get(payload, "failed").Bool()
	if statusCode <= 0 {
		if failed {
			statusCode = 500
		} else {
			statusCode = 200
		}
	}
	body := gjson.Get(payload, "fail.body").String()
	failureCode := strings.TrimSpace(gjson.Get(payload, "fail.code").String())

	result := coreauth.NewUsageResult(authIndex, provider, model, statusCode, body)
	if failed && failureCode == coreauth.ErrorCodeConnectionLifecycle {
		message := strings.TrimSpace(body)
		if message == "" {
			message = "connection lifecycle ended before an upstream response"
		}
		result.Success = false
		result.RetryAfter = nil
		result.Error = &coreauth.Error{
			Code:      coreauth.ErrorCodeConnectionLifecycle,
			Message:   message,
			Retryable: true,
		}
	}
	result.AccessTokenSHA256 = strings.TrimSpace(gjson.Get(payload, "access_token_sha256").String())
	r.coreManager.MarkResult(ctx, result)
}
