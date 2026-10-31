package auth

import (
	"context"
	"encoding/json"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClaudeQuotaHealthSeparatesCollectionFromExhaustion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		age      time.Duration
		eligible bool
		failure  string
		status   string
	}{
		{"available", time.Minute, true, "", "healthy"},
		{"exhausted", time.Minute, false, "", "healthy"},
		{"warning before expiry", 10 * time.Minute, true, "", "degraded"},
		{"expired", 31 * time.Minute, true, "", "stale"},
		{"schema failed with usable cache", time.Minute, true, "usage_schema", "degraded"},
		{"untrusted diagnostic ignored", time.Minute, true, "secret-account-name", "healthy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := quotaTestAuth("private-account@example.test", "claude")
			a.Metadata = map[string]any{"access_token": "synthetic-secret"}
			a.EnsureIndex()
			data := quotaTestAccount(quotaTestNow, time.Hour, time.Hour)
			data.ObservedAt = quotaTestNow.Add(-tc.age)
			data.AuthIndex = a.Index
			data.CredentialFingerprint = AccessTokenSHA256(a)
			data.Eligible = &tc.eligible
			data.Usage = json.RawMessage(`{"five_hour":{"utilization":0,"resets_at":null}}`)
			snap := claudeQuotaSnapshot{ObservedAt: quotaTestNow, Accounts: map[string]claudeQuotaAccount{a.ID: data}, RetryState: map[string]claudeQuotaRetry{a.ID: {AuthIndex: a.Index, CredentialFingerprint: AccessTokenSHA256(a), LastError: tc.failure}}}
			raw, _ := json.Marshal(snap)
			path := t.TempDir() + "/quota.json"
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			health := ReadClaudeQuotaHealth(path, []*Auth{a}, quotaTestNow)
			if health.Status != tc.status || health.Total != 1 {
				t.Fatalf("health=%+v", health)
			}
			raw, _ = json.Marshal(health)
			for _, secret := range []string{a.ID, a.Index, AccessTokenSHA256(a), "synthetic-secret", "secret-account-name"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("leaked diagnostic %s", raw)
				}
			}
			if tc.failure == "usage_schema" && health.Errors["usage_schema"] != 1 {
				t.Fatalf("missing schema error: %+v", health)
			}
		})
	}
}

func TestClaudeQuotaHealthRejectsReplacedCredentialsAndOldHeartbeat(t *testing.T) {
	a := quotaTestAuth("account", "claude")
	a.Metadata = map[string]any{"access_token": "replacement"}
	a.EnsureIndex()
	data := quotaTestAccount(quotaTestNow, time.Hour, time.Hour)
	data.ObservedAt = quotaTestNow
	data.AuthIndex = a.Index
	data.CredentialFingerprint = AccessTokenSHA256(a)
	data.Usage = json.RawMessage(`{}`)
	path := quotaTestSnapshot(t, quotaTestNow.Add(-11*time.Minute), map[string]claudeQuotaAccount{a.ID: data})
	if h := ReadClaudeQuotaHealth(path, []*Auth{a}, quotaTestNow); h.Status != "degraded" {
		t.Fatalf("heartbeat: %+v", h)
	}
	a.Metadata["access_token"] = "new-token"
	if h := ReadClaudeQuotaHealth(path, []*Auth{a}, quotaTestNow); h.Status != "stale" || h.Missing != 1 {
		t.Fatalf("replacement: %+v", h)
	}
	if h := ReadClaudeQuotaHealth(t.TempDir()+"/missing", []*Auth{a}, quotaTestNow); h.Reason != "snapshot_unavailable" {
		t.Fatalf("missing: %+v", h)
	}
}

func TestClaudeQuotaRefreshFailureIsNotExhaustion(t *testing.T) {
	a := quotaTestAuth("account", "claude")
	a.Metadata = map[string]any{"access_token": "synthetic"}
	a.EnsureIndex()
	snap := claudeQuotaSnapshot{ObservedAt: quotaTestNow, Accounts: map[string]claudeQuotaAccount{}, RetryState: map[string]claudeQuotaRetry{a.ID: {AuthIndex: a.Index, CredentialFingerprint: AccessTokenSHA256(a), LastError: "usage_schema", NextAttemptAt: quotaTestNow.Add(time.Minute)}}}
	raw, _ := json.Marshal(snap)
	path := t.TempDir() + "/quota.json"
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := (&ClaudeQuotaSelector{SnapshotPath: path}).pick(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, []*Auth{a}, quotaTestNow)
	quota, ok := err.(*ClaudeQuotaError)
	if !ok || quota.StatusCode() != 503 || quota.Reason != "collector_refresh_failed" || quota.Code != "claude_quota_unavailable" {
		t.Fatalf("error=%+v", err)
	}
	if strings.Contains(quota.Message, "exhausted") {
		t.Fatalf("misleading message %s", quota.Message)
	}
}

func TestClaudeQuotaHealthEmptyInventoryStillValidatesSnapshot(t *testing.T) {
	if h := ReadClaudeQuotaHealth(t.TempDir()+"/missing", nil, quotaTestNow); h.Status != "stale" || h.Reason != "snapshot_unavailable" {
		t.Fatalf("missing snapshot: %+v", h)
	}
	path := quotaTestSnapshot(t, quotaTestNow, map[string]claudeQuotaAccount{})
	if h := ReadClaudeQuotaHealth(path, nil, quotaTestNow); h.Status != "degraded" || h.Reason != "no_claude_credentials" {
		t.Fatalf("empty inventory: %+v", h)
	}
}
