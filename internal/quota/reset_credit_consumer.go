package quota

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPIHome/internal/cluster"
	log "github.com/sirupsen/logrus"
)

const resetCreditConsumeLeaseDuration = 2 * time.Minute

type ResetCreditConsumeInput struct {
	CredentialID      string
	RedeemRequestID   string
	ExpectedExpiresAt time.Time
}

type ResetCreditConsumeResult struct {
	CredentialID      string
	RedeemRequestID   string
	IdempotentReplay  bool
	RecollectAccepted int
}

// ResetCreditConsumeError is a redacted error suitable for the Management API.
type ResetCreditConsumeError struct {
	Code           string
	Message        string
	Retryable      bool
	HTTPStatus     int
	UpstreamStatus int
	Cause          error
}

func (e *ResetCreditConsumeError) Error() string {
	if e == nil {
		return "quota reset credit consume failed"
	}
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	return "quota reset credit consume failed"
}

func (e *ResetCreditConsumeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ConsumeResetCredit spends one Codex reset credit through the Home-owned
// credential. The database claim prevents concurrent Home instances from
// spending against the same snapshot, and the caller-provided redeem ID is
// preserved across ambiguous retries.
func (c *Collector) ConsumeResetCredit(ctx context.Context, input ResetCreditConsumeInput) (ResetCreditConsumeResult, error) {
	result := ResetCreditConsumeResult{
		CredentialID:    strings.TrimSpace(input.CredentialID),
		RedeemRequestID: strings.TrimSpace(input.RedeemRequestID),
	}
	if c == nil || c.repo == nil {
		return result, &ResetCreditConsumeError{Code: "RESET_CREDIT_CONSUMER_UNAVAILABLE", Message: "reset-credit consumption is unavailable", Retryable: true, HTTPStatus: http.StatusServiceUnavailable}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := c.options.Now().UTC()
	claim, errClaim := c.repo.ClaimQuotaResetCreditConsume(ctx, cluster.QuotaResetCreditConsumeClaim{
		CredentialID: result.CredentialID, RedeemRequestID: result.RedeemRequestID,
		ExpectedExpiresAt: input.ExpectedExpiresAt, Owner: c.options.Owner,
		Now: now, LeaseDuration: resetCreditConsumeLeaseDuration,
	})
	if errClaim != nil {
		return result, errClaim
	}
	if claim.AlreadySucceeded {
		result.IdempotentReplay = true
		result.RecollectAccepted = c.triggerResetCreditRecollection(ctx, result.CredentialID)
		return result, nil
	}

	auth, _, errAuth := c.repo.GetAuth(ctx, result.CredentialID)
	if errAuth != nil || auth == nil {
		consumeErr := &ResetCreditConsumeError{Code: "RESET_CREDIT_AUTH_RESOLVE_FAILED", Message: "credential could not be resolved for reset-credit consumption", Retryable: true, HTTPStatus: http.StatusServiceUnavailable, Cause: errAuth}
		c.finishResetCreditConsume(ctx, result, false, consumeErr)
		return result, consumeErr
	}
	if c.options.ResolveAuth != nil {
		resolveCtx, cancelResolve := context.WithTimeout(ctx, c.options.ProbeTimeout)
		resolved, errResolve := c.options.ResolveAuth(resolveCtx, auth)
		cancelResolve()
		if errResolve != nil || resolved == nil {
			consumeErr := &ResetCreditConsumeError{Code: "RESET_CREDIT_AUTH_RESOLVE_FAILED", Message: "credential could not be refreshed for reset-credit consumption", Retryable: true, HTTPStatus: http.StatusServiceUnavailable, Cause: errResolve}
			c.finishResetCreditConsume(ctx, result, false, consumeErr)
			return result, consumeErr
		}
		auth = resolved
	}

	errPost := c.postCodexResetCredit(ctx, auth, result.RedeemRequestID)
	if errPost != nil && (errPost.statusCode == http.StatusUnauthorized || errPost.statusCode == http.StatusForbidden) && c.options.ForceRefreshAuth != nil {
		refreshCtx, cancelRefresh := context.WithTimeout(ctx, c.options.ProbeTimeout)
		refreshed, errRefresh := c.options.ForceRefreshAuth(refreshCtx, auth)
		cancelRefresh()
		if errRefresh != nil || refreshed == nil {
			consumeErr := &ResetCreditConsumeError{Code: "RESET_CREDIT_AUTH_REFRESH_FAILED", Message: "credential refresh failed after upstream authorization rejection", Retryable: true, HTTPStatus: http.StatusServiceUnavailable, Cause: errRefresh}
			c.finishResetCreditConsume(ctx, result, false, consumeErr)
			return result, consumeErr
		}
		auth = refreshed
		errPost = c.postCodexResetCredit(ctx, auth, result.RedeemRequestID)
	}
	if errPost != nil {
		consumeErr := resetCreditConsumeErrorFromProbe(errPost)
		c.finishResetCreditConsume(ctx, result, false, consumeErr)
		return result, consumeErr
	}

	completionCtx := context.WithoutCancel(ctx)
	if errComplete := c.repo.CompleteQuotaResetCreditConsume(completionCtx, result.CredentialID, result.RedeemRequestID, c.options.Owner, true, false, "", 0, c.options.Now().UTC()); errComplete != nil {
		return result, &ResetCreditConsumeError{Code: "RESET_CREDIT_STATE_PERSIST_FAILED", Message: "reset credit was accepted upstream but Home could not persist completion state", Retryable: true, HTTPStatus: http.StatusServiceUnavailable, Cause: errComplete}
	}
	result.RecollectAccepted = c.triggerResetCreditRecollection(ctx, result.CredentialID)
	return result, nil
}

func (c *Collector) postCodexResetCredit(ctx context.Context, auth *coreauth.Auth, redeemRequestID string) *probeError {
	body, errMarshal := json.Marshal(map[string]string{"redeem_request_id": strings.TrimSpace(redeemRequestID)})
	if errMarshal != nil {
		return &probeError{code: "RESET_CREDIT_REQUEST_INVALID", message: "Reset-credit request could not be encoded.", retryable: false}
	}
	headers := http.Header{
		"Accept":       []string{"application/json"},
		"Content-Type": []string{"application/json"},
		"OpenAI-Beta":  []string{"codex-1"},
		"User-Agent":   []string{codexUserAgent},
	}
	if accountID := quotaMetadataString(auth.Metadata, "account_id", "accountId", "chatgpt_account_id", "chatgptAccountId"); accountID != "" {
		headers.Set("Chatgpt-Account-Id", accountID)
	}
	_, _, errRequest := c.probeRequest(ctx, auth, http.MethodPost, c.options.CodexResetCreditsConsumeURL, body, headers)
	return errRequest
}

func (c *Collector) finishResetCreditConsume(ctx context.Context, result ResetCreditConsumeResult, success bool, consumeErr *ResetCreditConsumeError) {
	if c == nil || c.repo == nil {
		return
	}
	retryable := consumeErr != nil && consumeErr.Retryable
	errorCode := ""
	upstreamStatus := 0
	if consumeErr != nil {
		errorCode = consumeErr.Code
		upstreamStatus = consumeErr.UpstreamStatus
	}
	completionCtx := context.WithoutCancel(ctx)
	if errComplete := c.repo.CompleteQuotaResetCreditConsume(completionCtx, result.CredentialID, result.RedeemRequestID, c.options.Owner, success, retryable, errorCode, upstreamStatus, c.options.Now().UTC()); errComplete != nil {
		log.WithError(errComplete).WithField("credential_id", result.CredentialID).Warn("quota reset-credit consume completion could not be persisted")
	}
}

func (c *Collector) triggerResetCreditRecollection(ctx context.Context, credentialID string) int {
	if c == nil {
		return 0
	}
	accepted, errTrigger := c.TriggerCollection(context.WithoutCancel(ctx), map[string]struct{}{strings.TrimSpace(credentialID): {}}, map[string]struct{}{"codex": {}})
	if errTrigger != nil {
		log.WithError(errTrigger).WithField("credential_id", credentialID).Warn("quota reset-credit recollection could not be queued")
		return 0
	}
	return accepted
}

func resetCreditConsumeErrorFromProbe(failure *probeError) *ResetCreditConsumeError {
	if failure == nil {
		return nil
	}
	code := "RESET_CREDIT_UPSTREAM_FAILED"
	message := "upstream reset-credit consumption failed"
	httpStatus := http.StatusBadGateway
	retryable := failure.retryable
	if failure.statusCode == http.StatusUnauthorized || failure.statusCode == http.StatusForbidden {
		code = "RESET_CREDIT_AUTH_REJECTED"
		message = "upstream rejected the credential after one refresh retry"
		retryable = false
	} else if failure.statusCode == http.StatusTooManyRequests {
		code = "RESET_CREDIT_UPSTREAM_RATE_LIMITED"
		message = "upstream rate limited reset-credit consumption"
		retryable = true
	} else if failure.statusCode >= http.StatusBadRequest && failure.statusCode < http.StatusInternalServerError {
		code = "RESET_CREDIT_UPSTREAM_REJECTED"
		message = "upstream rejected reset-credit consumption"
		retryable = false
	}
	return &ResetCreditConsumeError{
		Code: code, Message: message, Retryable: retryable, HTTPStatus: httpStatus,
		UpstreamStatus: failure.statusCode,
	}
}
