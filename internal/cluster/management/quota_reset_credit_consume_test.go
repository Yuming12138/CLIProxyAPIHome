package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPIHome/internal/cluster"
	quotacollector "github.com/router-for-me/CLIProxyAPIHome/internal/quota"
)

type fakeQuotaResetCreditConsumer struct {
	input  quotacollector.ResetCreditConsumeInput
	result quotacollector.ResetCreditConsumeResult
	err    error
	calls  int
}

func (f *fakeQuotaResetCreditConsumer) ConsumeResetCredit(_ context.Context, input quotacollector.ResetCreditConsumeInput) (quotacollector.ResetCreditConsumeResult, error) {
	f.calls++
	f.input = input
	return f.result, f.err
}

func TestConsumeQuotaResetCreditAccepted(t *testing.T) {
	handler, closeRepo := newUsageObservabilityTestHandler(t)
	defer closeRepo()
	expiresAt := time.Date(2026, 8, 1, 3, 3, 9, 0, time.UTC)
	consumer := &fakeQuotaResetCreditConsumer{result: quotacollector.ResetCreditConsumeResult{
		CredentialID: "credential-a", RedeemRequestID: "6885d7c5-c5d8-46d6-a37d-f0c52e49232e", RecollectAccepted: 1,
	}}
	handler.SetQuotaResetCreditConsumer(consumer)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/quota/credentials/:credential_id/reset-credits/consume", handler.ConsumeQuotaResetCredit)
	body := `{"redeem_request_id":"6885d7c5-c5d8-46d6-a37d-f0c52e49232e","expected_expires_at":"` + expiresAt.Format(time.RFC3339) + `"}`
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/quota/credentials/credential-a/reset-credits/consume", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("consume status = %d body=%s", response.Code, response.Body.String())
	}
	if consumer.calls != 1 || consumer.input.CredentialID != "credential-a" || consumer.input.RedeemRequestID != "6885d7c5-c5d8-46d6-a37d-f0c52e49232e" || !consumer.input.ExpectedExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected consume input: calls=%d input=%+v", consumer.calls, consumer.input)
	}
	var payload map[string]any
	if errDecode := json.Unmarshal(response.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if payload["status"] != "ok" || payload["recollect_running"] != true {
		t.Fatalf("unexpected consume response: %#v", payload)
	}
}

func TestConsumeQuotaResetCreditValidatesExpectedExpiry(t *testing.T) {
	handler, closeRepo := newUsageObservabilityTestHandler(t)
	defer closeRepo()
	consumer := &fakeQuotaResetCreditConsumer{}
	handler.SetQuotaResetCreditConsumer(consumer)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/quota/credentials/:credential_id/reset-credits/consume", handler.ConsumeQuotaResetCredit)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/quota/credentials/credential-a/reset-credits/consume", strings.NewReader(`{"redeem_request_id":"6885d7c5-c5d8-46d6-a37d-f0c52e49232e","expected_expires_at":"tomorrow"}`)))

	if response.Code != http.StatusBadRequest || consumer.calls != 0 || !strings.Contains(response.Body.String(), "INVALID_EXPECTED_EXPIRES_AT") {
		t.Fatalf("invalid expiry response = %d %s calls=%d", response.Code, response.Body.String(), consumer.calls)
	}
}

func TestConsumeQuotaResetCreditMapsSnapshotConflict(t *testing.T) {
	handler, closeRepo := newUsageObservabilityTestHandler(t)
	defer closeRepo()
	consumer := &fakeQuotaResetCreditConsumer{err: cluster.ErrQuotaResetCreditSnapshotStale}
	handler.SetQuotaResetCreditConsumer(consumer)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/quota/credentials/:credential_id/reset-credits/consume", handler.ConsumeQuotaResetCredit)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/quota/credentials/credential-a/reset-credits/consume", strings.NewReader(`{"redeem_request_id":"6885d7c5-c5d8-46d6-a37d-f0c52e49232e","expected_expires_at":"2026-08-01T03:03:09Z"}`)))

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "RESET_CREDIT_SNAPSHOT_STALE") {
		t.Fatalf("snapshot conflict response = %d %s", response.Code, response.Body.String())
	}
}

func TestConsumeQuotaResetCreditUnsupportedWithoutConsumer(t *testing.T) {
	handler, closeRepo := newUsageObservabilityTestHandler(t)
	defer closeRepo()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/quota/credentials/:credential_id/reset-credits/consume", handler.ConsumeQuotaResetCredit)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/quota/credentials/credential-a/reset-credits/consume", strings.NewReader(`{}`)))
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "RESET_CREDIT_CONSUME_UNSUPPORTED") {
		t.Fatalf("unsupported response = %d %s", response.Code, response.Body.String())
	}
}

func TestQuotaResetCreditConsumeCapabilityTracksConsumer(t *testing.T) {
	handler, closeRepo := newUsageObservabilityTestHandler(t)
	defer closeRepo()
	gin.SetMode(gin.TestMode)

	readCapability := func() bool {
		response := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(response)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/capabilities", nil)
		handler.GetCapabilities(ctx)
		var payload struct {
			Capabilities map[string]bool `json:"capabilities"`
		}
		if errDecode := json.Unmarshal(response.Body.Bytes(), &payload); errDecode != nil {
			t.Fatalf("decode capabilities: %v", errDecode)
		}
		return payload.Capabilities["quota_reset_credit_consume"]
	}

	if readCapability() {
		t.Fatal("consume capability is true without an injected consumer")
	}
	handler.SetQuotaResetCreditConsumer(&fakeQuotaResetCreditConsumer{})
	if !readCapability() {
		t.Fatal("consume capability is false with an injected consumer")
	}
}
