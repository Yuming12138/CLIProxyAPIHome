package quota

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPIHome/internal/cluster"
)

func TestQuotaSnapshotObservationUsesOfficialAccountResetBeforeSnapshotExpiry(t *testing.T) {
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	resetAt := now.Add(2 * time.Hour)
	expiresAt := now.Add(30 * time.Minute)
	observation := quotaSnapshotObservation(cluster.QuotaSnapshotWrite{
		QuotaStatus: "exhausted",
		ExpiresAt:   &expiresAt,
		Windows: []cluster.QuotaWindow{{
			Scope:      "account",
			Status:     "exhausted",
			ResetAt:    &resetAt,
			ObservedAt: now,
		}},
	}, now)
	if observation.QuotaStatus != "exhausted" || observation.RetryAfter == nil || *observation.RetryAfter != 2*time.Hour {
		t.Fatalf("observation = %+v, want exhausted retryAfter=2h", observation)
	}
}

func TestQuotaSnapshotObservationFallsBackToSnapshotExpiry(t *testing.T) {
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(15 * time.Minute)
	observation := quotaSnapshotObservation(cluster.QuotaSnapshotWrite{
		QuotaStatus: "exhausted",
		ExpiresAt:   &expiresAt,
		Windows: []cluster.QuotaWindow{{
			Scope:      "account",
			Status:     "exhausted",
			ObservedAt: now,
		}},
	}, now)
	if observation.RetryAfter == nil || *observation.RetryAfter != 15*time.Minute {
		t.Fatalf("retryAfter = %v, want 15m", observation.RetryAfter)
	}
}

func TestQuotaSnapshotObservationHealthyClearsWithoutRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	observation := quotaSnapshotObservation(cluster.QuotaSnapshotWrite{QuotaStatus: "healthy"}, now)
	if observation.QuotaStatus != "healthy" || observation.RetryAfter != nil {
		t.Fatalf("observation = %+v, want healthy without retryAfter", observation)
	}
}
