package cluster

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestQuotaResetCreditConsumeClaimIsSerializedAndIdempotent(t *testing.T) {
	repo, closeRepo := newBillingTestRepository(t, context.Background())
	defer closeRepo()
	seedQuotaSnapshotAuth(t, repo, "codex-reset-consume", "codex", "Codex Reset", map[string]any{"type": "codex", "access_token": "test-token"})

	now := time.Date(2026, 7, 31, 2, 0, 0, 0, time.UTC)
	creditExpiresAt := now.Add(8 * time.Hour)
	snapshotExpiresAt := now.Add(30 * time.Minute)
	availableCount := 1
	if _, errSeed := repo.UpsertQuotaSnapshot(context.Background(), QuotaSnapshotWrite{
		CredentialID: "codex-reset-consume", QuotaStatus: "exhausted", CollectionStatus: "success", Source: "active_probe",
		ObservedAt: &now, ExpiresAt: &snapshotExpiresAt, LastSuccessAt: &now, NextProbeAt: &snapshotExpiresAt,
		ParserVersion: QuotaSnapshotVersion("codex"), CollectorVersion: QuotaSnapshotVersion("codex"),
		ResetCredits: &QuotaResetCredits{AvailableCount: &availableCount, ObservedAt: now, Credits: []QuotaResetCredit{{
			ID: "provider-credit-id", Status: "available", GrantedAt: now.Add(-time.Hour), ExpiresAt: &creditExpiresAt,
		}}}, ReplaceResetCredits: true,
	}); errSeed != nil {
		t.Fatalf("seed quota snapshot: %v", errSeed)
	}

	claimInput := QuotaResetCreditConsumeClaim{
		CredentialID: "codex-reset-consume", RedeemRequestID: "19b4ac3c-70e8-4fd7-aee6-43d999b02239",
		ExpectedExpiresAt: creditExpiresAt, Owner: "home-a", Now: now, LeaseDuration: time.Minute,
	}
	claim, errClaim := repo.ClaimQuotaResetCreditConsume(context.Background(), claimInput)
	if errClaim != nil || claim.AlreadySucceeded || !claim.SnapshotObservedAt.Equal(now) {
		t.Fatalf("first claim = %+v, %v", claim, errClaim)
	}

	competing := claimInput
	competing.RedeemRequestID = "49e92337-ac14-4a2b-809e-cd3d64004463"
	competing.Owner = "home-b"
	if _, errCompeting := repo.ClaimQuotaResetCreditConsume(context.Background(), competing); !errors.Is(errCompeting, ErrQuotaResetCreditConsumeInProgress) {
		t.Fatalf("competing claim error = %v, want in progress", errCompeting)
	}

	if errComplete := repo.CompleteQuotaResetCreditConsume(context.Background(), claimInput.CredentialID, claimInput.RedeemRequestID, claimInput.Owner, true, false, "", 0, now.Add(time.Second)); errComplete != nil {
		t.Fatalf("complete consume: %v", errComplete)
	}
	replay := claimInput
	replay.Now = now.Add(2 * time.Second)
	replayed, errReplay := repo.ClaimQuotaResetCreditConsume(context.Background(), replay)
	if errReplay != nil || !replayed.AlreadySucceeded {
		t.Fatalf("idempotent replay = %+v, %v", replayed, errReplay)
	}

	item, errGet := repo.GetQuotaCredential(context.Background(), claimInput.CredentialID, now.Add(2*time.Second))
	if errGet != nil {
		t.Fatalf("GetQuotaCredential: %v", errGet)
	}
	if item.Freshness != "stale" || item.NextProbeAt == nil || item.NextProbeAt.After(now.Add(time.Second)) {
		t.Fatalf("successful consume did not invalidate source snapshot: %+v", item)
	}
}

func TestQuotaResetCreditConsumeClaimRejectsStaleOrMismatchedSnapshot(t *testing.T) {
	repo, closeRepo := newBillingTestRepository(t, context.Background())
	defer closeRepo()
	seedQuotaSnapshotAuth(t, repo, "codex-reset-validation", "codex", "Codex Reset", map[string]any{"type": "codex", "access_token": "test-token"})

	now := time.Date(2026, 7, 31, 3, 0, 0, 0, time.UTC)
	creditExpiresAt := now.Add(4 * time.Hour)
	snapshotExpiresAt := now.Add(30 * time.Minute)
	availableCount := 1
	if _, errSeed := repo.UpsertQuotaSnapshot(context.Background(), QuotaSnapshotWrite{
		CredentialID: "codex-reset-validation", QuotaStatus: "low", CollectionStatus: "success", Source: "active_probe",
		ObservedAt: &now, ExpiresAt: &snapshotExpiresAt,
		ParserVersion: QuotaSnapshotVersion("codex"), CollectorVersion: QuotaSnapshotVersion("codex"),
		ResetCredits: &QuotaResetCredits{AvailableCount: &availableCount, ObservedAt: now, Credits: []QuotaResetCredit{{
			ID: "credit-validation", Status: "available", GrantedAt: now.Add(-time.Hour), ExpiresAt: &creditExpiresAt,
		}}}, ReplaceResetCredits: true,
	}); errSeed != nil {
		t.Fatalf("seed quota snapshot: %v", errSeed)
	}

	input := QuotaResetCreditConsumeClaim{
		CredentialID: "codex-reset-validation", RedeemRequestID: "1a92db67-916d-4100-8bb4-22d09ae61187",
		ExpectedExpiresAt: creditExpiresAt.Add(time.Minute), Owner: "home-a", Now: now,
	}
	if _, errMismatch := repo.ClaimQuotaResetCreditConsume(context.Background(), input); !errors.Is(errMismatch, ErrQuotaResetCreditExpiryMismatch) {
		t.Fatalf("expiry mismatch error = %v", errMismatch)
	}

	input.ExpectedExpiresAt = creditExpiresAt
	input.Now = snapshotExpiresAt
	if _, errStale := repo.ClaimQuotaResetCreditConsume(context.Background(), input); !errors.Is(errStale, ErrQuotaResetCreditSnapshotStale) {
		t.Fatalf("stale snapshot error = %v", errStale)
	}
}

func TestQuotaResetCreditConsumeTableIsMigrationOnly(t *testing.T) {
	repo, closeRepo := newBillingTestRepository(t, context.Background())
	defer closeRepo()
	db, errDB := repo.database()
	if errDB != nil {
		t.Fatalf("database: %v", errDB)
	}
	if !db.Migrator().HasTable(&QuotaResetCreditConsumeRecord{}) {
		t.Fatal("quota_reset_credit_consume was not migrated")
	}
	for _, model := range homeDatabaseModels {
		if model.name == "quota_reset_credit_consume" {
			t.Fatal("runtime consume coordination table entered the portable snapshot registry")
		}
	}
}
