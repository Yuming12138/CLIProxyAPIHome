package home

import (
	"context"
	"net/http"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPIHome/internal/config"
)

func TestRecordQuotaObservationAppliesAccountExhaustedCooldown(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "codex-plus", Index: "codex-plus", Provider: "codex", Status: coreauth.StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	rt := &Runtime{coreManager: manager}

	cooldown := 2 * time.Hour
	before := time.Now().UTC()
	rt.RecordQuotaObservation(context.Background(), auth, "exhausted", &cooldown)

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("GetByID(%s) missing", auth.ID)
	}
	if updated.Status != coreauth.StatusError || !updated.Unavailable || !updated.Quota.Exceeded {
		t.Fatalf("auth state = status %v unavailable %v quota %+v, want exhausted cooldown", updated.Status, updated.Unavailable, updated.Quota)
	}
	if updated.LastError == nil || updated.LastError.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("LastError = %+v, want HTTP 429", updated.LastError)
	}
	if updated.Success != 0 || updated.Failed != 0 {
		t.Fatalf("quota observation request counters = success %d failed %d, want zero", updated.Success, updated.Failed)
	}
	wantMin := before.Add(cooldown - 2*time.Second)
	wantMax := before.Add(cooldown + 2*time.Second)
	if updated.NextRetryAfter.Before(wantMin) || updated.NextRetryAfter.After(wantMax) {
		t.Fatalf("NextRetryAfter = %v, want around %v", updated.NextRetryAfter, before.Add(cooldown))
	}
}

func TestRecordQuotaObservationClearsCooldownAfterHealthyOrLowSnapshot(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "codex-reset", Index: "codex-reset", Provider: "codex", Status: coreauth.StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	rt := &Runtime{coreManager: manager}

	cooldown := time.Hour
	rt.RecordQuotaObservation(context.Background(), auth, "exhausted", &cooldown)
	rt.RecordQuotaObservation(context.Background(), auth, "low", nil)

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("GetByID(%s) missing", auth.ID)
	}
	if updated.Unavailable || updated.Quota.Exceeded || !updated.NextRetryAfter.IsZero() || updated.Status != coreauth.StatusActive {
		t.Fatalf("low snapshot did not clear quota cooldown: %+v", updated)
	}
	if updated.Success != 0 || updated.Failed != 0 {
		t.Fatalf("quota recovery request counters = success %d failed %d, want zero", updated.Success, updated.Failed)
	}
}

func TestRecordQuotaObservationClearsOnlyQuotaModelStates(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "codex-model-recovery", Index: "codex-model-recovery", Provider: "codex", Status: coreauth.StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	quotaModel := "gpt-quota"
	forbiddenModel := "gpt-forbidden"

	cooldown := time.Hour
	manager.MarkResult(context.Background(), coreauth.Result{
		AuthID: auth.ID, Provider: auth.Provider, Model: quotaModel,
		Error:      &coreauth.Error{Code: "quota_exhausted", Message: "quota exhausted", Retryable: true, HTTPStatus: http.StatusTooManyRequests},
		RetryAfter: &cooldown,
	})
	manager.MarkResult(context.Background(), coreauth.Result{
		AuthID: auth.ID, Provider: auth.Provider, Model: forbiddenModel,
		Error: &coreauth.Error{Code: "permission_denied", Message: "permission denied", HTTPStatus: http.StatusForbidden},
	})

	rt := &Runtime{coreManager: manager}
	rt.RecordQuotaObservation(context.Background(), auth, "healthy", nil)

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("updated credential missing")
	}
	quotaState := updated.ModelStates[quotaModel]
	if quotaState == nil || quotaState.Status != coreauth.StatusActive || quotaState.Unavailable || quotaState.Quota.Exceeded || quotaState.LastError != nil {
		t.Fatalf("quota model state was not recovered: %+v", quotaState)
	}
	forbiddenState := updated.ModelStates[forbiddenModel]
	if forbiddenState == nil || forbiddenState.Status != coreauth.StatusError || !forbiddenState.Unavailable || forbiddenState.LastError == nil || forbiddenState.LastError.HTTPStatus != http.StatusForbidden {
		t.Fatalf("non-quota model state was changed: %+v", forbiddenState)
	}
	if updated.Unavailable {
		t.Fatalf("credential remained unavailable after one model recovered: %+v", updated)
	}
}

func TestRecordQuotaObservationDoesNotClearDisabledOrUnauthorizedState(t *testing.T) {
	tests := []struct {
		name string
		auth *coreauth.Auth
	}{
		{
			name: "disabled",
			auth: &coreauth.Auth{
				ID: "codex-disabled", Index: "codex-disabled", Provider: "codex", Disabled: true, Status: coreauth.StatusDisabled,
				StatusMessage: "unauthorized", Unavailable: true,
				Quota: coreauth.QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: time.Now().Add(time.Hour)},
			},
		},
		{
			name: "unauthorized",
			auth: &coreauth.Auth{
				ID: "codex-unauthorized", Index: "codex-unauthorized", Provider: "codex", Status: coreauth.StatusError,
				StatusMessage: "unauthorized", Unavailable: true, NextRetryAfter: time.Now().Add(time.Hour),
				Quota:     coreauth.QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: time.Now().Add(time.Hour)},
				LastError: &coreauth.Error{Code: "authentication_error", Message: "credential unauthorized", HTTPStatus: http.StatusUnauthorized},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := coreauth.NewManager(nil, nil, nil)
			if _, errRegister := manager.Register(context.Background(), test.auth); errRegister != nil {
				t.Fatalf("Register() error = %v", errRegister)
			}
			rt := &Runtime{coreManager: manager}
			rt.RecordQuotaObservation(context.Background(), test.auth, "healthy", nil)
			updated, ok := manager.GetByID(test.auth.ID)
			if !ok || updated == nil {
				t.Fatal("updated credential missing")
			}
			if !updated.Quota.Exceeded || !updated.Unavailable || updated.Status == coreauth.StatusActive {
				t.Fatalf("protected auth state was cleared: %+v", updated)
			}
		})
	}
}

func TestRecordQuotaObservationIgnoresUnknownSnapshot(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "codex-unknown", Index: "codex-unknown", Provider: "codex", Status: coreauth.StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	rt := &Runtime{coreManager: manager}
	rt.RecordQuotaObservation(context.Background(), auth, "unknown", nil)
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("GetByID(%s) missing", auth.ID)
	}
	if updated.Unavailable || updated.Quota.Exceeded || !updated.NextRetryAfter.IsZero() {
		t.Fatalf("unknown snapshot changed auth state: %+v", updated)
	}
}

func TestNewRuntimeKeepsCentralQuotaCoolingEnabled(t *testing.T) {
	rt, errRuntime := NewRuntime(&config.Config{DisableCooling: true})
	if errRuntime != nil {
		t.Fatalf("NewRuntime() error = %v", errRuntime)
	}
	t.Cleanup(rt.Stop)

	auth := &coreauth.Auth{ID: "codex-central", Index: "codex-central", Provider: "codex", Status: coreauth.StatusActive}
	if _, errRegister := rt.CoreManager().Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	cooldown := time.Hour
	rt.RecordQuotaObservation(context.Background(), auth, "exhausted", &cooldown)

	updated, ok := rt.CoreManager().GetByID(auth.ID)
	if !ok || updated == nil || !updated.Unavailable || !updated.Quota.Exceeded || updated.NextRetryAfter.IsZero() {
		t.Fatalf("central quota cooldown was disabled by downstream config: %+v", updated)
	}
}

func TestNewRuntimeCentralQuotaCoolingDoesNotEnableTransientCooldowns(t *testing.T) {
	rt, errRuntime := NewRuntime(&config.Config{DisableCooling: true})
	if errRuntime != nil {
		t.Fatalf("NewRuntime() error = %v", errRuntime)
	}
	t.Cleanup(rt.Stop)

	auth := &coreauth.Auth{ID: "codex-transient", Index: "codex-transient", Provider: "codex", Status: coreauth.StatusActive}
	if _, errRegister := rt.CoreManager().Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	rt.CoreManager().MarkResult(context.Background(), coreauth.Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5",
		Error: &coreauth.Error{
			Message:    "transient upstream error",
			HTTPStatus: http.StatusBadGateway,
		},
	})

	updated, ok := rt.CoreManager().GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("credential missing")
	}
	state := updated.ModelStates["gpt-5"]
	if state == nil {
		t.Fatal("transient result did not record model state")
	}
	if !state.NextRetryAfter.IsZero() || updated.Unavailable || !updated.NextRetryAfter.IsZero() {
		t.Fatalf("central quota cooling created a transient dispatch blackout: auth=%+v model=%+v", updated, state)
	}
}

func TestNewRuntimeHonorsCredentialCoolingOverride(t *testing.T) {
	rt, errRuntime := NewRuntime(&config.Config{DisableCooling: true})
	if errRuntime != nil {
		t.Fatalf("NewRuntime() error = %v", errRuntime)
	}
	t.Cleanup(rt.Stop)

	auth := &coreauth.Auth{
		ID:       "codex-no-cooling",
		Index:    "codex-no-cooling",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"disable_cooling": true},
	}
	if _, errRegister := rt.CoreManager().Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	cooldown := time.Hour
	rt.RecordQuotaObservation(context.Background(), auth, "exhausted", &cooldown)

	updated, ok := rt.CoreManager().GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("credential missing")
	}
	if !updated.NextRetryAfter.IsZero() || !updated.Quota.NextRecoverAt.IsZero() {
		t.Fatalf("credential disable_cooling override retained a dispatch deadline: %+v", updated)
	}
}
