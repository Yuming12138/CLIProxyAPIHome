package home

import (
	"context"
	"net/http"
	"sort"
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
		r.reconcileQuotaRecovery(ctx, auth)
		return
	default:
		return
	}
	result.InternalObservation = true
	r.coreManager.MarkResult(ctx, result)
}

// reconcileQuotaRecovery clears only quota-derived runtime blocks after a
// fresh provider quota probe proves that capacity is available again.
func (r *Runtime) reconcileQuotaRecovery(ctx context.Context, observed *coreauth.Auth) {
	if r == nil || r.coreManager == nil || observed == nil {
		return
	}
	authID := strings.TrimSpace(observed.ID)
	if authID == "" {
		return
	}
	current, ok := r.coreManager.GetByID(authID)
	if !ok || current == nil || current.Disabled || current.Status == coreauth.StatusDisabled {
		return
	}

	models := make([]string, 0, len(current.ModelStates))
	for model, state := range current.ModelStates {
		if quotaRecoveryState(state) {
			models = append(models, model)
		}
	}
	sort.Strings(models)
	for _, model := range models {
		r.coreManager.MarkResult(ctx, coreauth.Result{
			AuthID:              authID,
			AuthIndex:           strings.TrimSpace(current.Index),
			Provider:            strings.TrimSpace(current.Provider),
			Model:               model,
			Success:             true,
			InternalObservation: true,
		})
	}

	current, ok = r.coreManager.GetByID(authID)
	if !ok || current == nil || current.Disabled || current.Status == coreauth.StatusDisabled {
		return
	}
	if !quotaRecoveryAvailability(current.Quota, current.LastError, current.StatusMessage) {
		return
	}
	r.coreManager.MarkResult(ctx, coreauth.Result{
		AuthID:              authID,
		AuthIndex:           strings.TrimSpace(current.Index),
		Provider:            strings.TrimSpace(current.Provider),
		Success:             true,
		InternalObservation: true,
	})
}

func quotaRecoveryState(state *coreauth.ModelState) bool {
	if state == nil || state.Status == coreauth.StatusDisabled {
		return false
	}
	return quotaRecoveryAvailability(state.Quota, state.LastError, state.StatusMessage)
}

func quotaRecoveryAvailability(quota coreauth.QuotaState, lastError *coreauth.Error, statusMessage string) bool {
	if lastError != nil {
		if lastError.HTTPStatus == http.StatusTooManyRequests || quotaRecoveryText(lastError.Code) || quotaRecoveryText(lastError.Message) {
			return true
		}
		if lastError.HTTPStatus != 0 || strings.TrimSpace(lastError.Code) != "" || strings.TrimSpace(lastError.Message) != "" {
			return false
		}
	}
	if quota.Exceeded && quotaRecoveryReason(quota.Reason) {
		return true
	}
	return quotaRecoveryText(statusMessage)
}

func quotaRecoveryReason(reason string) bool {
	normalized := strings.ToLower(strings.TrimSpace(reason))
	return normalized == "quota" ||
		normalized == "rate_limit" ||
		normalized == "rate limit" ||
		strings.Contains(normalized, "5h") ||
		strings.Contains(normalized, "7d") ||
		strings.Contains(normalized, "weekly")
}

func quotaRecoveryText(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", " ")
	return normalized == "quota exhausted" || normalized == "quota exceeded"
}
