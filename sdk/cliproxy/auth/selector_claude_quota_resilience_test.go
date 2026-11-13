package auth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func quotaTestBoundAuth(id, token string) *Auth {
	a := quotaTestAuth(id, "claude")
	a.Metadata = map[string]any{"access_token": token}
	a.EnsureIndex()
	return a
}

func quotaTestBoundAccount(a *Auth, observed time.Time, eligible bool, weekly, fiveHour time.Time) claudeQuotaAccount {
	return claudeQuotaAccount{
		ObservedAt:            observed,
		AuthIndex:             a.Index,
		CredentialFingerprint: AccessTokenSHA256(a),
		WeeklyReset:           weekly,
		FiveHourReset:         fiveHour,
		Eligible:              &eligible,
	}
}

func quotaTestMetadata(t *testing.T, err error) ClaudeQuotaErrorMetadata {
	t.Helper()
	var quotaErr *ClaudeQuotaError
	if !errors.As(err, &quotaErr) {
		t.Fatalf("error = %v, want ClaudeQuotaError", err)
	}
	raw, _ := json.Marshal(quotaErr)
	var meta ClaudeQuotaErrorMetadata
	if errJSON := json.Unmarshal(raw, &meta); errJSON != nil {
		t.Fatalf("invalid quota error JSON %s: %v", raw, errJSON)
	}
	return meta
}

func TestClaudeQuotaCoolingEligibleAccountIsNotExhaustion(t *testing.T) {
	for _, tc := range []struct {
		name       string
		eligibleA  bool
		until      time.Duration
		wantCode   string
		wantReason string
		wantRetry  int64
	}{
		{"eligible cooling account", true, 90 * time.Second, "claude_quota_unavailable", "eligible_account_cooling", 90},
		{"exhausted cooling account", false, 90 * time.Second, "claude_quota_exhausted", "", 7200},
		{"expired cooldown ignored", true, 0, "claude_quota_exhausted", "", 7200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := quotaTestBoundAuth("a", "token-a")
			b := quotaTestBoundAuth("b", "token-b")
			accountA := quotaTestBoundAccount(a, quotaTestNow, tc.eligibleA, quotaTestNow.Add(24*time.Hour), quotaTestNow.Add(time.Hour))
			accountA.Usage = json.RawMessage(`{"seven_day":{"utilization":100,"resets_at":"2026-10-29T12:00:00Z"}}`)
			accountB := quotaTestBoundAccount(b, quotaTestNow, false, quotaTestNow.Add(2*time.Hour), quotaTestNow.Add(time.Hour))
			accountB.Usage = json.RawMessage(`{"seven_day":{"utilization":100,"resets_at":"2026-10-28T14:00:00Z"}}`)
			selector := &ClaudeQuotaSelector{SnapshotPath: quotaTestSnapshot(t, quotaTestNow, map[string]claudeQuotaAccount{a.ID: accountA, b.ID: accountB}), Fallback: &FillFirstSelector{}}
			ctx := context.WithValue(context.Background(), claudeQuotaCoolingKey{}, []claudeQuotaCoolingAuth{{auth: a, until: quotaTestNow.Add(tc.until)}})
			picked, err := selector.pick(ctx, "claude", "claude-sonnet-4-6", cliproxyexecutor.Options{}, []*Auth{b}, quotaTestNow)
			if picked != nil {
				t.Fatalf("exhausted account selected: %s", picked.ID)
			}
			quotaTestError(t, err, tc.wantCode)
			meta := quotaTestMetadata(t, err)
			if meta.Reason != tc.wantReason || meta.RetryAfterSeconds != tc.wantRetry {
				t.Fatalf("metadata = %+v, want reason %q retry %d", meta, tc.wantReason, tc.wantRetry)
			}
			if tc.wantCode == "claude_quota_exhausted" && (meta.ResetAt == nil || !meta.ResetAt.Equal(quotaTestNow.Add(2*time.Hour))) {
				t.Fatalf("true exhaustion lost earliest reset: %+v", meta)
			}
		})
	}
}

func TestClaudeQuotaCoolingPicksEarliestCooldownEnd(t *testing.T) {
	accounts := map[string]claudeQuotaAccount{"a": quotaTestAccount(quotaTestNow, 24*time.Hour, time.Hour), "c": quotaTestAccount(quotaTestNow, 48*time.Hour, time.Hour)}
	selector := &ClaudeQuotaSelector{SnapshotPath: quotaTestSnapshot(t, quotaTestNow, accounts)}
	ctx := context.WithValue(context.Background(), claudeQuotaCoolingKey{}, []claudeQuotaCoolingAuth{
		{auth: quotaTestAuth("a", "claude"), until: quotaTestNow.Add(10 * time.Minute)},
		{auth: quotaTestAuth("c", "claude"), until: quotaTestNow.Add(30 * time.Second)},
	})
	// No Claude candidate remains; the unknown candidate would otherwise yield
	// an observation error rather than the cooling hint.
	_, err := selector.pick(ctx, "claude", "claude-sonnet-4-6", cliproxyexecutor.Options{}, []*Auth{quotaTestAuth("unknown", "claude")}, quotaTestNow)
	quotaTestError(t, err, "claude_quota_unavailable")
	if meta := quotaTestMetadata(t, err); meta.Reason != "eligible_account_cooling" || meta.RetryAfterSeconds != 30 {
		t.Fatalf("cooling metadata = %+v", meta)
	}
}

func TestClaudeQuotaManagerCooldownReportsCoolingNotExhaustion(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "single"
		if mixed {
			name = "mixed"
		}
		t.Run(name, func(t *testing.T) {
			for _, exhaustedA := range []bool{false, true} {
				now := time.Now().UTC()
				model := "claude-sonnet-4-6"
				a := quotaTestAuth(t.Name()+"-a", "claude")
				b := quotaTestAuth(t.Name()+"-b", "claude")
				accountA := quotaTestAccount(now, time.Hour, time.Hour)
				*accountA.Eligible = !exhaustedA
				accountB := quotaTestAccount(now, 2*time.Hour, time.Hour)
				*accountB.Eligible = false
				selector := &ClaudeQuotaSelector{SnapshotPath: quotaTestSnapshot(t, now, map[string]claudeQuotaAccount{a.ID: accountA, b.ID: accountB}), Fallback: &FillFirstSelector{}}
				m := quotaTestManager(t, selector, model, a, b)
				retry := 10 * time.Minute
				m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "claude", Model: model, Error: &Error{HTTPStatus: 429, Message: "rate limited"}, RetryAfter: &retry})
				var picked *Auth
				var err error
				if mixed {
					picked, _, _, err = m.pickNextMixed(context.Background(), []string{"claude"}, model, cliproxyexecutor.Options{}, nil)
				} else {
					picked, _, err = m.pickNext(context.Background(), "claude", model, cliproxyexecutor.Options{}, nil)
				}
				if picked != nil {
					t.Fatalf("exhaustedA=%v selected %s", exhaustedA, picked.ID)
				}
				if exhaustedA {
					quotaTestError(t, err, "claude_quota_exhausted")
					continue
				}
				quotaTestError(t, err, "claude_quota_unavailable")
				meta := quotaTestMetadata(t, err)
				if meta.Reason != "eligible_account_cooling" || meta.RetryAfterSeconds < 590 || meta.RetryAfterSeconds > 600 {
					t.Fatalf("cooling metadata = %+v", meta)
				}
				var quotaErr *ClaudeQuotaError
				errors.As(err, &quotaErr)
				if header := quotaErr.SafeResponseHeaders().Get("Retry-After"); header == "" || header == "0" {
					t.Fatalf("missing Retry-After header: %q", header)
				}
			}
		})
	}
}

func TestClaudeQuotaStaleLastResort(t *testing.T) {
	stale := quotaTestNow.Add(-31 * time.Minute)
	for _, tc := range []struct {
		name     string
		accounts func(a, b *Auth) map[string]claudeQuotaAccount
		want     string
		code     string
	}{
		{"stale eligible picked when no fresh account", func(a, b *Auth) map[string]claudeQuotaAccount {
			return map[string]claudeQuotaAccount{a.ID: quotaTestBoundAccount(a, stale, true, quotaTestNow.Add(24*time.Hour), quotaTestNow.Add(-time.Hour))}
		}, "a", ""},
		{"fresh eligible strictly preferred over earlier stale", func(a, b *Auth) map[string]claudeQuotaAccount {
			return map[string]claudeQuotaAccount{
				a.ID: quotaTestBoundAccount(a, stale, true, quotaTestNow.Add(time.Hour), quotaTestNow.Add(time.Hour)),
				b.ID: quotaTestBoundAccount(b, quotaTestNow, true, quotaTestNow.Add(72*time.Hour), quotaTestNow.Add(time.Hour)),
			}
		}, "b", ""},
		{"earliest weekly reset among stale accounts", func(a, b *Auth) map[string]claudeQuotaAccount {
			return map[string]claudeQuotaAccount{
				a.ID: quotaTestBoundAccount(a, stale, true, quotaTestNow.Add(48*time.Hour), quotaTestNow.Add(time.Hour)),
				b.ID: quotaTestBoundAccount(b, stale, true, quotaTestNow.Add(24*time.Hour), quotaTestNow.Add(time.Hour)),
			}
		}, "b", ""},
		{"stale eligible beats fresh exhausted", func(a, b *Auth) map[string]claudeQuotaAccount {
			return map[string]claudeQuotaAccount{
				a.ID: quotaTestBoundAccount(a, stale, true, quotaTestNow.Add(48*time.Hour), quotaTestNow.Add(time.Hour)),
				b.ID: quotaTestBoundAccount(b, quotaTestNow, false, quotaTestNow.Add(time.Hour), quotaTestNow.Add(time.Hour)),
			}
		}, "a", ""},
		{"stale ineligible never picked", func(a, b *Auth) map[string]claudeQuotaAccount {
			return map[string]claudeQuotaAccount{a.ID: quotaTestBoundAccount(a, stale, false, quotaTestNow.Add(24*time.Hour), quotaTestNow.Add(time.Hour))}
		}, "", "claude_quota_unavailable"},
		{"stale weekly reset passed", func(a, b *Auth) map[string]claudeQuotaAccount {
			return map[string]claudeQuotaAccount{a.ID: quotaTestBoundAccount(a, stale, true, quotaTestNow, quotaTestNow.Add(time.Hour))}
		}, "", "claude_quota_unavailable"},
		{"stale observation for another credential", func(a, b *Auth) map[string]claudeQuotaAccount {
			account := quotaTestBoundAccount(a, stale, true, quotaTestNow.Add(24*time.Hour), quotaTestNow.Add(time.Hour))
			account.CredentialFingerprint = AccessTokenSHA256(b)
			return map[string]claudeQuotaAccount{a.ID: account}
		}, "", "claude_quota_unavailable"},
		{"stale observation for another index", func(a, b *Auth) map[string]claudeQuotaAccount {
			account := quotaTestBoundAccount(a, stale, true, quotaTestNow.Add(24*time.Hour), quotaTestNow.Add(time.Hour))
			account.AuthIndex = b.Index
			return map[string]claudeQuotaAccount{a.ID: account}
		}, "", "claude_quota_unavailable"},
		{"stale with blocked model family", func(a, b *Auth) map[string]claudeQuotaAccount {
			account := quotaTestBoundAccount(a, stale, true, quotaTestNow.Add(24*time.Hour), quotaTestNow.Add(time.Hour))
			account.BlockedModelFamilies = []string{"sonnet"}
			return map[string]claudeQuotaAccount{a.ID: account}
		}, "", "claude_quota_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := quotaTestBoundAuth("a", "token-a")
			b := quotaTestBoundAuth("b", "token-b")
			selector := &ClaudeQuotaSelector{SnapshotPath: quotaTestSnapshot(t, quotaTestNow, tc.accounts(a, b)), Fallback: &FillFirstSelector{}}
			picked, err := selector.pick(context.Background(), "claude", "claude-sonnet-4-6", cliproxyexecutor.Options{}, []*Auth{a, b}, quotaTestNow)
			if tc.want != "" {
				if err != nil || picked == nil || picked.ID != tc.want {
					t.Fatalf("picked=%v err=%v, want %s", picked, err, tc.want)
				}
				return
			}
			if picked != nil {
				t.Fatalf("unsafe stale account selected: %s", picked.ID)
			}
			quotaTestError(t, err, tc.code)
		})
	}
}

func TestClaudeQuotaStaleEligibleCoolingIsReportedAsCooling(t *testing.T) {
	a := quotaTestBoundAuth("a", "token-a")
	b := quotaTestBoundAuth("b", "token-b")
	accounts := map[string]claudeQuotaAccount{
		a.ID: quotaTestBoundAccount(a, quotaTestNow.Add(-time.Hour), true, quotaTestNow.Add(24*time.Hour), quotaTestNow.Add(time.Hour)),
		b.ID: quotaTestBoundAccount(b, quotaTestNow, false, quotaTestNow.Add(2*time.Hour), quotaTestNow.Add(time.Hour)),
	}
	selector := &ClaudeQuotaSelector{SnapshotPath: quotaTestSnapshot(t, quotaTestNow, accounts)}
	ctx := context.WithValue(context.Background(), claudeQuotaCoolingKey{}, []claudeQuotaCoolingAuth{{auth: a, until: quotaTestNow.Add(time.Minute)}})
	_, err := selector.pick(ctx, "claude", "claude-sonnet-4-6", cliproxyexecutor.Options{}, []*Auth{b}, quotaTestNow)
	quotaTestError(t, err, "claude_quota_unavailable")
	if meta := quotaTestMetadata(t, err); meta.Reason != "eligible_account_cooling" || meta.RetryAfterSeconds != 60 {
		t.Fatalf("cooling metadata = %+v", meta)
	}
}
