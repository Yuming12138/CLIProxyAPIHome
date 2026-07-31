package management

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPIHome/internal/cluster"
	quotacollector "github.com/router-for-me/CLIProxyAPIHome/internal/quota"
)

// QuotaResetCreditConsumer spends one provider-issued reset credit using a
// Home-owned credential and queues an authoritative recollection afterward.
type QuotaResetCreditConsumer interface {
	ConsumeResetCredit(context.Context, quotacollector.ResetCreditConsumeInput) (quotacollector.ResetCreditConsumeResult, error)
}

// ConsumeQuotaResetCredit handles POST
// /quota/credentials/:credential_id/reset-credits/consume.
func (h *Handler) ConsumeQuotaResetCredit(c *gin.Context) {
	if h == nil || h.quotaResetCreditConsumer == nil {
		respondQuotaHTTPError(c, http.StatusNotFound, "RESET_CREDIT_CONSUME_UNSUPPORTED", "reset-credit consumption is not available on this runtime", false)
		return
	}
	credentialID := strings.TrimSpace(c.Param("credential_id"))
	if credentialID == "" {
		respondQuotaHTTPError(c, http.StatusNotFound, "QUOTA_CREDENTIAL_NOT_FOUND", "quota credential not found", false)
		return
	}
	var body struct {
		RedeemRequestID   string `json:"redeem_request_id"`
		ExpectedExpiresAt string `json:"expected_expires_at"`
	}
	decoder := json.NewDecoder(io.LimitReader(c.Request.Body, 64<<10))
	if errDecode := decoder.Decode(&body); errDecode != nil {
		respondQuotaHTTPError(c, http.StatusBadRequest, "INVALID_BODY", "reset-credit consume body must be a JSON object", false)
		return
	}
	var trailing any
	if errTrailing := decoder.Decode(&trailing); errTrailing != nil && !errors.Is(errTrailing, io.EOF) {
		respondQuotaHTTPError(c, http.StatusBadRequest, "INVALID_BODY", "reset-credit consume body must contain one JSON object", false)
		return
	} else if errTrailing == nil {
		respondQuotaHTTPError(c, http.StatusBadRequest, "INVALID_BODY", "reset-credit consume body must contain one JSON object", false)
		return
	}
	redeemRequestID := strings.TrimSpace(body.RedeemRequestID)
	parsedRedeemID, errRedeemID := uuid.Parse(redeemRequestID)
	if errRedeemID != nil || redeemRequestID == "" {
		respondQuotaHTTPError(c, http.StatusBadRequest, "INVALID_REDEEM_REQUEST_ID", "redeem_request_id must be a valid UUID", false)
		return
	}
	expectedExpiresAt, errExpiry := time.Parse(time.RFC3339Nano, strings.TrimSpace(body.ExpectedExpiresAt))
	if errExpiry != nil || expectedExpiresAt.IsZero() {
		respondQuotaHTTPError(c, http.StatusBadRequest, "INVALID_EXPECTED_EXPIRES_AT", "expected_expires_at must be an RFC3339 timestamp", false)
		return
	}

	requestCtx := context.Background()
	if c.Request != nil && c.Request.Context() != nil {
		requestCtx = c.Request.Context()
	}
	ctx, cancel := context.WithTimeout(requestCtx, 45*time.Second)
	defer cancel()
	result, errConsume := h.quotaResetCreditConsumer.ConsumeResetCredit(ctx, quotacollector.ResetCreditConsumeInput{
		CredentialID: credentialID, RedeemRequestID: parsedRedeemID.String(), ExpectedExpiresAt: expectedExpiresAt.UTC(),
	})
	if errConsume != nil {
		respondQuotaResetCreditConsumeError(c, errConsume)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "ok", "credential_id": result.CredentialID,
		"redeem_request_id": result.RedeemRequestID, "idempotent_replay": result.IdempotentReplay,
		"recollect_accepted": result.RecollectAccepted, "recollect_running": result.RecollectAccepted > 0,
	})
}

func respondQuotaResetCreditConsumeError(c *gin.Context, errConsume error) {
	switch {
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditCredentialNotFound):
		respondQuotaHTTPError(c, http.StatusNotFound, "QUOTA_CREDENTIAL_NOT_FOUND", "quota credential not found", false)
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditProviderInvalid):
		respondQuotaHTTPError(c, http.StatusBadRequest, "RESET_CREDIT_PROVIDER_INVALID", "credential must be a Codex OAuth credential", false)
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditCredentialDisabled):
		respondQuotaHTTPError(c, http.StatusConflict, "RESET_CREDIT_CREDENTIAL_DISABLED", "credential is disabled", false)
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditSnapshotStale):
		respondQuotaHTTPError(c, http.StatusConflict, "RESET_CREDIT_SNAPSHOT_STALE", "a fresh complete quota snapshot is required", true)
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditUnavailable):
		respondQuotaHTTPError(c, http.StatusConflict, "RESET_CREDIT_UNAVAILABLE", "no current reset credit is available", false)
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditExpiryMismatch):
		respondQuotaHTTPError(c, http.StatusConflict, "RESET_CREDIT_EXPIRY_MISMATCH", "expected_expires_at does not match the current earliest reset credit", false)
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditConsumeInProgress):
		c.Header("Retry-After", "30")
		respondQuotaHTTPError(c, http.StatusConflict, "RESET_CREDIT_CONSUME_IN_PROGRESS", "a reset-credit consume is already in progress", true)
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditRecollectRequired):
		respondQuotaHTTPError(c, http.StatusConflict, "RESET_CREDIT_RECOLLECT_REQUIRED", "collect a newer quota snapshot before using another redeem request ID", true)
	case errors.Is(errConsume, cluster.ErrQuotaResetCreditConsumeFailed):
		respondQuotaHTTPError(c, http.StatusConflict, "RESET_CREDIT_PREVIOUSLY_FAILED", "this redeem request ID has a terminal failure", false)
	default:
		var consumeError *quotacollector.ResetCreditConsumeError
		if errors.As(errConsume, &consumeError) {
			status := consumeError.HTTPStatus
			if status <= 0 {
				status = http.StatusBadGateway
			}
			respondQuotaHTTPError(c, status, consumeError.Code, consumeError.Message, consumeError.Retryable)
			return
		}
		status := quotaReadErrorStatus(errConsume)
		respondQuotaHTTPError(c, status, "RESET_CREDIT_CONSUME_FAILED", "reset-credit consumption failed", status >= http.StatusInternalServerError)
	}
}
