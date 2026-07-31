package home

import (
	"context"
	"net/http"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
)

const defaultQuotaObservationCooldown = 30 * time.Minute

// RecordQuotaObservation applies authoritative quota observations to dispatch scheduling.
func (r *Runtime) RecordQuotaObservation(ctx context.Context, auth *coreauth.Auth, quotaStatus string, retryAfter *time.Duration) {
	if r == nil || r.coreManager == nil || auth == nil || strings.TrimSpace(auth.ID) == "" {
		return
	}
	quotaStatus = strings.ToLower(strings.TrimSpace(quotaStatus))
	result := coreauth.Result{
		AuthID:    strings.TrimSpace(auth.ID),
		AuthIndex: strings.TrimSpace(auth.Index),
		Provider:  strings.TrimSpace(auth.Provider),
	}
	switch quotaStatus {
	case "exhausted":
		cooldown := retryAfter
		if cooldown == nil || *cooldown <= 0 {
			fallback := defaultQuotaObservationCooldown
			cooldown = &fallback
		}
		result.Success = false
		result.RetryAfter = cooldown
		result.Error = &coreauth.Error{
			Code:       "quota_exhausted",
			Message:    "quota exhausted",
			Retryable:  true,
			HTTPStatus: http.StatusTooManyRequests,
		}
	case "healthy", "low":
		result.Success = true
	default:
		return
	}
	r.coreManager.MarkResult(ctx, result)
}
