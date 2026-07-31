package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPIHome/internal/cliproxy/auth"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const defaultQuotaResetCreditConsumeLease = 2 * time.Minute

const (
	quotaResetCreditConsumeClaimed   = "claimed"
	quotaResetCreditConsumeSucceeded = "succeeded"
	quotaResetCreditConsumeRetryable = "retryable"
	quotaResetCreditConsumeFailed    = "failed"
)

var (
	ErrQuotaResetCreditCredentialNotFound = errors.New("quota reset credit credential not found")
	ErrQuotaResetCreditProviderInvalid    = errors.New("quota reset credit credential must be Codex OAuth")
	ErrQuotaResetCreditCredentialDisabled = errors.New("quota reset credit credential is disabled")
	ErrQuotaResetCreditSnapshotStale      = errors.New("quota reset credit snapshot is not fresh and complete")
	ErrQuotaResetCreditUnavailable        = errors.New("quota reset credit is unavailable")
	ErrQuotaResetCreditExpiryMismatch     = errors.New("quota reset credit expiry does not match the current earliest credit")
	ErrQuotaResetCreditConsumeInProgress  = errors.New("quota reset credit consume is already in progress")
	ErrQuotaResetCreditRecollectRequired  = errors.New("quota reset credit snapshot must be recollected before another consume")
	ErrQuotaResetCreditConsumeFailed      = errors.New("quota reset credit consume previously failed")
	ErrQuotaResetCreditConsumeLeaseLost   = errors.New("quota reset credit consume lease is no longer owned")
)

// QuotaResetCreditConsumeRecord serializes reset-credit consumption per
// credential and preserves the redeem request ID across ambiguous retries.
// It is a runtime coordination table and is intentionally excluded from
// portable database snapshots.
type QuotaResetCreditConsumeRecord struct {
	CredentialID       string     `gorm:"column:credential_id;primaryKey;size:128"`
	RedeemRequestID    string     `gorm:"column:redeem_request_id;not null;size:36;uniqueIndex"`
	ExpectedExpiresAt  time.Time  `gorm:"column:expected_expires_at;not null"`
	CreditKey          string     `gorm:"column:credit_key;not null;size:64"`
	SnapshotObservedAt time.Time  `gorm:"column:snapshot_observed_at;not null;index"`
	State              string     `gorm:"column:state;not null;size:32;index"`
	Retryable          bool       `gorm:"column:retryable;not null;default:false"`
	LeaseOwner         string     `gorm:"column:lease_owner;size:256"`
	LeaseExpiresAt     *time.Time `gorm:"column:lease_expires_at;index"`
	ErrorCode          string     `gorm:"column:error_code;size:128"`
	UpstreamStatus     int        `gorm:"column:upstream_status;not null;default:0"`
	CompletedAt        *time.Time `gorm:"column:completed_at"`
	CreatedAt          time.Time  `gorm:"column:created_at"`
	UpdatedAt          time.Time  `gorm:"column:updated_at"`
}

func (QuotaResetCreditConsumeRecord) TableName() string {
	return "quota_reset_credit_consume"
}

type QuotaResetCreditConsumeClaim struct {
	CredentialID      string
	RedeemRequestID   string
	ExpectedExpiresAt time.Time
	Owner             string
	Now               time.Time
	LeaseDuration     time.Duration
}

type QuotaResetCreditConsumeClaimResult struct {
	AlreadySucceeded   bool
	SnapshotObservedAt time.Time
}

// ClaimQuotaResetCreditConsume atomically validates the authoritative quota
// snapshot and acquires the per-credential consume lease.
func (r *Repository) ClaimQuotaResetCreditConsume(ctx context.Context, input QuotaResetCreditConsumeClaim) (QuotaResetCreditConsumeClaimResult, error) {
	credentialID := strings.TrimSpace(input.CredentialID)
	redeemRequestID := strings.TrimSpace(input.RedeemRequestID)
	owner := strings.TrimSpace(input.Owner)
	if credentialID == "" || redeemRequestID == "" || owner == "" || input.ExpectedExpiresAt.IsZero() {
		return QuotaResetCreditConsumeClaimResult{}, fmt.Errorf("quota reset credit consume claim fields are required")
	}
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expectedExpiresAt := input.ExpectedExpiresAt.UTC()
	leaseDuration := input.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultQuotaResetCreditConsumeLease
	}
	db, errDB := r.database()
	if errDB != nil {
		return QuotaResetCreditConsumeClaimResult{}, errDB
	}

	result := QuotaResetCreditConsumeClaimResult{}
	errTransaction := db.WithContext(contextOrBackground(ctx)).Transaction(func(tx *gorm.DB) error {
		var authRecord AuthRecord
		errAuth := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("uuid = ?", credentialID).First(&authRecord).Error
		if errors.Is(errAuth, gorm.ErrRecordNotFound) {
			return ErrQuotaResetCreditCredentialNotFound
		}
		if errAuth != nil {
			return errAuth
		}
		auth, errConvert := RecordToAuth(&authRecord)
		if errConvert != nil {
			return errConvert
		}
		if normalizeQuotaProviderID(auth.Provider) != "codex" || quotaCredentialType(auth) == "provider_api_key" {
			return ErrQuotaResetCreditProviderInvalid
		}
		if authRecord.Disabled || authRecord.Status == coreauth.StatusDisabled {
			return ErrQuotaResetCreditCredentialDisabled
		}

		var existing QuotaResetCreditConsumeRecord
		errExisting := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("credential_id = ?", credentialID).First(&existing).Error
		if errExisting != nil && !errors.Is(errExisting, gorm.ErrRecordNotFound) {
			return errExisting
		}
		if errExisting == nil {
			sameRequest := existing.RedeemRequestID == redeemRequestID
			if sameRequest && !existing.ExpectedExpiresAt.Equal(expectedExpiresAt) {
				return ErrQuotaResetCreditExpiryMismatch
			}
			if sameRequest && existing.State == quotaResetCreditConsumeSucceeded {
				result.AlreadySucceeded = true
				result.SnapshotObservedAt = existing.SnapshotObservedAt.UTC()
				return nil
			}
			if existing.State == quotaResetCreditConsumeClaimed && existing.LeaseExpiresAt != nil && existing.LeaseExpiresAt.After(now) {
				return ErrQuotaResetCreditConsumeInProgress
			}
			if sameRequest && existing.State == quotaResetCreditConsumeFailed && !existing.Retryable {
				return ErrQuotaResetCreditConsumeFailed
			}
		}

		var snapshot QuotaSnapshotRecord
		errSnapshot := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("credential_id = ?", credentialID).First(&snapshot).Error
		if errors.Is(errSnapshot, gorm.ErrRecordNotFound) {
			return ErrQuotaResetCreditSnapshotStale
		}
		if errSnapshot != nil {
			return errSnapshot
		}
		if !quotaResetCreditSnapshotConsumable(snapshot, auth.Provider, now) {
			return ErrQuotaResetCreditSnapshotStale
		}
		resetCredits := quotaResetCreditsFromJSON(snapshot.ResetCredits)
		credit, okCredit := earliestConsumableQuotaResetCredit(resetCredits, now)
		if !okCredit {
			return ErrQuotaResetCreditUnavailable
		}
		if credit.ExpiresAt == nil || !credit.ExpiresAt.Equal(expectedExpiresAt) {
			return ErrQuotaResetCreditExpiryMismatch
		}
		creditKey := quotaResetCreditOpaqueKey(credit.ID)

		if errExisting == nil {
			sameRequest := existing.RedeemRequestID == redeemRequestID
			if sameRequest && existing.CreditKey != creditKey {
				return ErrQuotaResetCreditExpiryMismatch
			}
			if !sameRequest && (snapshot.ObservedAt == nil || !snapshot.ObservedAt.After(existing.SnapshotObservedAt)) {
				return ErrQuotaResetCreditRecollectRequired
			}
		}

		leaseExpiresAt := now.Add(leaseDuration)
		record := QuotaResetCreditConsumeRecord{
			CredentialID: credentialID, RedeemRequestID: redeemRequestID, ExpectedExpiresAt: expectedExpiresAt,
			CreditKey: creditKey, SnapshotObservedAt: snapshot.ObservedAt.UTC(), State: quotaResetCreditConsumeClaimed,
			LeaseOwner: owner, LeaseExpiresAt: &leaseExpiresAt, CreatedAt: now, UpdatedAt: now,
		}
		if errors.Is(errExisting, gorm.ErrRecordNotFound) {
			if errCreate := tx.Create(&record).Error; errCreate != nil {
				return errCreate
			}
		} else {
			updates := map[string]any{
				"redeem_request_id": redeemRequestID, "expected_expires_at": expectedExpiresAt,
				"credit_key": creditKey, "snapshot_observed_at": snapshot.ObservedAt.UTC(),
				"state": quotaResetCreditConsumeClaimed, "retryable": false, "lease_owner": owner,
				"lease_expires_at": leaseExpiresAt, "error_code": "", "upstream_status": 0,
				"completed_at": nil, "updated_at": now,
			}
			if errUpdate := tx.Model(&QuotaResetCreditConsumeRecord{}).Where("credential_id = ?", credentialID).Updates(updates).Error; errUpdate != nil {
				return errUpdate
			}
		}
		result.SnapshotObservedAt = snapshot.ObservedAt.UTC()
		return nil
	})
	return result, errTransaction
}

// CompleteQuotaResetCreditConsume releases a claimed consume operation. A
// success also expires the source snapshot so another credit cannot be spent
// until a new authoritative collection is persisted.
func (r *Repository) CompleteQuotaResetCreditConsume(ctx context.Context, credentialID string, redeemRequestID string, owner string, success bool, retryable bool, errorCode string, upstreamStatus int, now time.Time) error {
	credentialID = strings.TrimSpace(credentialID)
	redeemRequestID = strings.TrimSpace(redeemRequestID)
	owner = strings.TrimSpace(owner)
	if credentialID == "" || redeemRequestID == "" || owner == "" {
		return fmt.Errorf("quota reset credit consume completion fields are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	db, errDB := r.database()
	if errDB != nil {
		return errDB
	}
	return db.WithContext(contextOrBackground(ctx)).Transaction(func(tx *gorm.DB) error {
		var record QuotaResetCreditConsumeRecord
		if errFind := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("credential_id = ?", credentialID).First(&record).Error; errFind != nil {
			return errFind
		}
		if record.RedeemRequestID == redeemRequestID && record.State == quotaResetCreditConsumeSucceeded && success {
			return nil
		}
		if record.RedeemRequestID != redeemRequestID || record.State != quotaResetCreditConsumeClaimed || record.LeaseOwner != owner {
			return ErrQuotaResetCreditConsumeLeaseLost
		}
		state := quotaResetCreditConsumeSucceeded
		if !success {
			state = quotaResetCreditConsumeFailed
			if retryable {
				state = quotaResetCreditConsumeRetryable
			}
		}
		updates := map[string]any{
			"state": state, "retryable": retryable, "lease_owner": "", "lease_expires_at": nil,
			"error_code": strings.TrimSpace(errorCode), "upstream_status": upstreamStatus,
			"completed_at": now, "updated_at": now,
		}
		if errUpdate := tx.Model(&QuotaResetCreditConsumeRecord{}).Where("credential_id = ?", credentialID).Updates(updates).Error; errUpdate != nil {
			return errUpdate
		}
		if success {
			if errExpire := tx.Model(&QuotaSnapshotRecord{}).Where("credential_id = ?", credentialID).Updates(map[string]any{
				"expires_at": now, "next_probe_at": now, "updated_at": now,
			}).Error; errExpire != nil {
				return errExpire
			}
		}
		return nil
	})
}

func quotaResetCreditSnapshotConsumable(snapshot QuotaSnapshotRecord, provider string, now time.Time) bool {
	if snapshot.ObservedAt == nil || snapshot.ExpiresAt == nil || !snapshot.ExpiresAt.After(now) {
		return false
	}
	if snapshot.ObservedAt.After(now.Add(quotaMaxFutureObservationSkew)) {
		return false
	}
	if snapshot.CollectionStatus != "success" || snapshot.CollectorVersion < QuotaSnapshotVersion(provider) {
		return false
	}
	switch strings.TrimSpace(snapshot.Source) {
	case "active_probe", "mixed":
		return true
	default:
		return false
	}
}

func earliestConsumableQuotaResetCredit(value *QuotaResetCredits, now time.Time) (QuotaResetCredit, bool) {
	if value == nil || value.AvailableCount == nil || *value.AvailableCount <= 0 {
		return QuotaResetCredit{}, false
	}
	for _, credit := range value.Credits {
		if credit.Status == "available" && credit.ExpiresAt != nil && credit.ExpiresAt.After(now) {
			return credit, true
		}
	}
	return QuotaResetCredit{}, false
}

func quotaResetCreditOpaqueKey(creditID string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(creditID)))
	return hex.EncodeToString(digest[:])
}

// QuotaResetCreditPublicKey returns a stable, non-reversible identifier that
// management clients can use for deterministic retry IDs without exposing the
// provider-issued credit ID.
func QuotaResetCreditPublicKey(creditID string) string {
	value := quotaResetCreditOpaqueKey(creditID)
	if len(value) > 24 {
		return value[:24]
	}
	return value
}
