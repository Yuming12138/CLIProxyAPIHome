package quota

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPIHome/internal/cluster"
)

func TestConsumeResetCreditRefreshesOnceAndRecollects(t *testing.T) {
	repo := newCollectorTestRepository(t)
	now := time.Date(2026, 7, 31, 4, 0, 0, 0, time.UTC)
	seedCollectorAuth(t, repo, "codex-consume", map[string]any{
		"type": "codex", "access_token": "old-access-token", "account_id": "account-test",
	})
	creditExpiresAt := now.Add(6 * time.Hour)
	snapshotObservedAt := now.Add(-time.Minute)
	snapshotExpiresAt := now.Add(29 * time.Minute)
	availableCount := 1
	if _, errSeed := repo.UpsertQuotaSnapshot(context.Background(), cluster.QuotaSnapshotWrite{
		CredentialID: "codex-consume", QuotaStatus: "exhausted", CollectionStatus: "success", Source: "active_probe",
		ObservedAt: &snapshotObservedAt, ExpiresAt: &snapshotExpiresAt, LastSuccessAt: &snapshotObservedAt,
		ParserVersion: cluster.QuotaSnapshotVersion("codex"), CollectorVersion: cluster.QuotaSnapshotVersion("codex"),
		ResetCredits: &cluster.QuotaResetCredits{AvailableCount: &availableCount, ObservedAt: snapshotObservedAt, Credits: []cluster.QuotaResetCredit{{
			ID: "credit-consume", Status: "available", GrantedAt: now.Add(-time.Hour), ExpiresAt: &creditExpiresAt,
		}}}, ReplaceResetCredits: true,
	}); errSeed != nil {
		t.Fatalf("seed quota snapshot: %v", errSeed)
	}

	var consumeRequests atomic.Int32
	var usageRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/consume":
			attempt := consumeRequests.Add(1)
			if request.Header.Get("Chatgpt-Account-Id") != "account-test" {
				t.Errorf("missing account header")
			}
			var body map[string]string
			if errDecode := json.NewDecoder(request.Body).Decode(&body); errDecode != nil || body["redeem_request_id"] != "2ac2d36c-8fdf-4ac1-99e4-7024b19819db" {
				t.Errorf("unexpected consume body: %#v error=%v", body, errDecode)
			}
			if attempt == 1 {
				if request.Header.Get("Authorization") != "Bearer old-access-token" {
					t.Errorf("first consume did not use old token")
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if request.Header.Get("Authorization") != "Bearer new-access-token" {
				t.Errorf("retry did not use refreshed token")
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/usage":
			usageRequests.Add(1)
			_, _ = w.Write([]byte(`{"plan_type":"pro","rate_limit":{"primary_window":{"used_percent":0,"limit_window_seconds":18000,"reset_after_seconds":18000},"secondary_window":{"used_percent":0,"limit_window_seconds":604800,"reset_after_seconds":604800}},"rate_limit_reset_credits":{"available_count":0}}`))
		case "/credits":
			_, _ = w.Write([]byte(`{"available_count":0,"credits":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var forceRefreshes atomic.Int32
	collector := NewCollector(repo, Options{
		Owner: "home-test", HomeID: "home-test", Now: func() time.Time { return now },
		CodexUsageURL: server.URL + "/usage", CodexResetCreditsURL: server.URL + "/credits",
		CodexResetCreditsConsumeURL: server.URL + "/consume",
		ResolveAuth: func(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
			return auth, nil
		},
		ForceRefreshAuth: func(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
			forceRefreshes.Add(1)
			refreshed := auth.Clone()
			refreshed.Metadata = map[string]any{"type": "codex", "access_token": "new-access-token", "account_id": "account-test"}
			return refreshed, nil
		},
	})
	input := ResetCreditConsumeInput{
		CredentialID: "codex-consume", RedeemRequestID: "2ac2d36c-8fdf-4ac1-99e4-7024b19819db",
		ExpectedExpiresAt: creditExpiresAt,
	}
	result, errConsume := collector.ConsumeResetCredit(context.Background(), input)
	if errConsume != nil {
		t.Fatalf("ConsumeResetCredit() error = %v", errConsume)
	}
	if result.IdempotentReplay || result.RecollectAccepted != 1 {
		t.Fatalf("ConsumeResetCredit() result = %+v", result)
	}
	collector.Wait()
	if consumeRequests.Load() != 2 || forceRefreshes.Load() != 1 || usageRequests.Load() != 1 {
		t.Fatalf("requests: consume=%d refresh=%d usage=%d", consumeRequests.Load(), forceRefreshes.Load(), usageRequests.Load())
	}

	replay, errReplay := collector.ConsumeResetCredit(context.Background(), input)
	if errReplay != nil || !replay.IdempotentReplay {
		t.Fatalf("idempotent replay = %+v, %v", replay, errReplay)
	}
	collector.Wait()
	if consumeRequests.Load() != 2 {
		t.Fatalf("idempotent replay posted upstream: consume=%d", consumeRequests.Load())
	}

	item, errGet := repo.GetQuotaCredential(context.Background(), input.CredentialID, now.Add(time.Minute))
	if errGet != nil {
		t.Fatalf("GetQuotaCredential() error = %v", errGet)
	}
	if item.Freshness != "fresh" || item.ResetCredits == nil || item.ResetCredits.AvailableCount == nil || *item.ResetCredits.AvailableCount != 0 {
		t.Fatalf("forced recollection did not persist the reset result: %+v", item)
	}
}

func TestConsumeResetCreditPersistsSuccessAfterCallerCancellation(t *testing.T) {
	repo := newCollectorTestRepository(t)
	now := time.Date(2026, 7, 31, 5, 0, 0, 0, time.UTC)
	creditExpiresAt := seedResetCreditConsumeState(t, repo, "codex-cancel-success", now)

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	collector := NewCollector(repo, Options{
		Owner: "home-test", HomeID: "home-test", Now: func() time.Time { return now },
		CodexResetCreditsConsumeURL: "https://reset-credit.test/consume",
		ResolveAuth: func(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
			return auth, nil
		},
		HTTPClient: func(_ *coreauth.Auth, _ time.Duration) (*http.Client, error) {
			return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				cancelRequest()
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       http.NoBody,
					Request:    request,
				}, nil
			})}, nil
		},
	})
	input := ResetCreditConsumeInput{
		CredentialID: "codex-cancel-success", RedeemRequestID: "90ce21d5-c156-4ba2-845d-694ce4d36e2d",
		ExpectedExpiresAt: creditExpiresAt,
	}
	result, errConsume := collector.ConsumeResetCredit(requestCtx, input)
	if errConsume != nil {
		t.Fatalf("ConsumeResetCredit() error after caller cancellation = %v", errConsume)
	}
	if result.IdempotentReplay {
		t.Fatalf("first consume unexpectedly reported idempotent replay: %+v", result)
	}
	collector.Wait()

	replay, errReplay := collector.ConsumeResetCredit(context.Background(), input)
	if errReplay != nil || !replay.IdempotentReplay {
		t.Fatalf("persisted success replay = %+v, %v", replay, errReplay)
	}
	collector.Wait()
}

func TestConsumeResetCreditReleasesLeaseAfterCallerCancellation(t *testing.T) {
	repo := newCollectorTestRepository(t)
	now := time.Date(2026, 7, 31, 6, 0, 0, 0, time.UTC)
	creditExpiresAt := seedResetCreditConsumeState(t, repo, "codex-cancel-failure", now)

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	collector := NewCollector(repo, Options{
		Owner: "home-test", HomeID: "home-test", Now: func() time.Time { return now },
		CodexResetCreditsConsumeURL: "https://reset-credit.test/consume",
		ResolveAuth: func(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
			cancelRequest()
			return auth, nil
		},
		HTTPClient: func(_ *coreauth.Auth, _ time.Duration) (*http.Client, error) {
			return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return nil, request.Context().Err()
			})}, nil
		},
	})
	input := ResetCreditConsumeInput{
		CredentialID: "codex-cancel-failure", RedeemRequestID: "83280b0f-49c4-4bcd-ad55-9b7080084712",
		ExpectedExpiresAt: creditExpiresAt,
	}
	if _, errConsume := collector.ConsumeResetCredit(requestCtx, input); errConsume == nil {
		t.Fatal("ConsumeResetCredit() succeeded after caller cancellation")
	}

	claim, errClaim := repo.ClaimQuotaResetCreditConsume(context.Background(), cluster.QuotaResetCreditConsumeClaim{
		CredentialID: input.CredentialID, RedeemRequestID: input.RedeemRequestID,
		ExpectedExpiresAt: input.ExpectedExpiresAt, Owner: "home-test", Now: now,
	})
	if errClaim != nil || claim.AlreadySucceeded {
		t.Fatalf("retryable claim after cancellation = %+v, %v", claim, errClaim)
	}
}

func seedResetCreditConsumeState(t *testing.T, repo *cluster.Repository, credentialID string, now time.Time) time.Time {
	t.Helper()
	seedCollectorAuth(t, repo, credentialID, map[string]any{
		"type": "codex", "access_token": "test-access-token", "account_id": "account-test",
	})
	creditExpiresAt := now.Add(6 * time.Hour)
	snapshotObservedAt := now.Add(-time.Minute)
	snapshotExpiresAt := now.Add(29 * time.Minute)
	availableCount := 1
	if _, errSeed := repo.UpsertQuotaSnapshot(context.Background(), cluster.QuotaSnapshotWrite{
		CredentialID: credentialID, QuotaStatus: "exhausted", CollectionStatus: "success", Source: "active_probe",
		ObservedAt: &snapshotObservedAt, ExpiresAt: &snapshotExpiresAt, LastSuccessAt: &snapshotObservedAt,
		ParserVersion: cluster.QuotaSnapshotVersion("codex"), CollectorVersion: cluster.QuotaSnapshotVersion("codex"),
		ResetCredits: &cluster.QuotaResetCredits{AvailableCount: &availableCount, ObservedAt: snapshotObservedAt, Credits: []cluster.QuotaResetCredit{{
			ID: "credit-" + credentialID, Status: "available", GrantedAt: now.Add(-time.Hour), ExpiresAt: &creditExpiresAt,
		}}}, ReplaceResetCredits: true,
	}); errSeed != nil {
		t.Fatalf("seed quota snapshot: %v", errSeed)
	}
	return creditExpiresAt
}
