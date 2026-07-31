package home

import (
	"context"
	"net/http"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
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
