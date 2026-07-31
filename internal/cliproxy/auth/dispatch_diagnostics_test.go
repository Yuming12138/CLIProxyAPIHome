package auth

import (
	"strings"
	"testing"
	"time"
)

func TestDispatchAuthStateDetailOmitsCredentialMaterial(t *testing.T) {
	now := time.Now()
	retryAt := now.Add(time.Minute)
	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:             "123456789-sensitive-suffix",
		Provider:       "codex",
		Status:         StatusError,
		StatusMessage:  "status-secret",
		Unavailable:    true,
		NextRetryAfter: retryAt,
		Quota: QuotaState{
			Reason: "quota-secret",
		},
		Attributes: map[string]string{"api_key": "attribute-secret"},
		Metadata:   map[string]any{"access_token": "metadata-secret"},
		ModelStates: map[string]*ModelState{
			"gpt-5": {
				Status:         StatusError,
				StatusMessage:  "model-secret",
				Unavailable:    true,
				NextRetryAfter: retryAt,
			},
		},
	}

	detail := manager.dispatchAuthStateDetail(auth, "gpt-5", "blocked_other", now)
	for _, secret := range []string{
		"sensitive-suffix",
		"status-secret",
		"quota-secret",
		"attribute-secret",
		"metadata-secret",
		"model-secret",
	} {
		if strings.Contains(detail, secret) {
			t.Fatalf("dispatchAuthStateDetail() exposed %q in %q", secret, detail)
		}
	}
	for _, expected := range []string{
		"auth=12345678",
		"filter=blocked_other",
		"provider=codex",
		"status=error",
		"unavailable=true",
		"model_status=error",
		"model_unavailable=true",
	} {
		if !strings.Contains(detail, expected) {
			t.Fatalf("dispatchAuthStateDetail() = %q, want %q", detail, expected)
		}
	}
}
