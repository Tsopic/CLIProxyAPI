package auth

import "time"

// ClaudeQuotaHealth reports collector health, not whether a model has quota.
// It is computed from current credential bindings, never copied from a report.
type ClaudeQuotaHealth struct {
	Status    string         `json:"status"`
	CheckedAt time.Time      `json:"checked_at"`
	Total     int            `json:"total"`
	Fresh     int            `json:"fresh"`
	Warning   int            `json:"warning"`
	Stale     int            `json:"stale"`
	Missing   int            `json:"missing"`
	Failing   int            `json:"failing"`
	Backoff   int            `json:"backoff"`
	Reason    string         `json:"reason,omitempty"`
	Errors    map[string]int `json:"errors,omitempty"`
}

func safeClaudeCollectorError(value string) string {
	switch value {
	case "transport", "management_http", "wrapper_schema", "wrapper_parse", "upstream_http", "usage_parse", "usage_schema":
		return value
	default:
		return ""
	}
}

// ReadClaudeQuotaHealth performs no upstream requests and exposes no credential IDs.
func ReadClaudeQuotaHealth(path string, credentials []*Auth, now time.Time) ClaudeQuotaHealth {
	health := ClaudeQuotaHealth{Status: "healthy", CheckedAt: now.UTC()}
	snapshot, err := (&ClaudeQuotaSelector{SnapshotPath: path}).load(now)
	for _, credential := range credentials {
		if !isClaudeQuotaAuth(credential) || credential.Disabled {
			continue
		}
		health.Total++
		account, exists := snapshot.Accounts[credential.ID]
		bound := exists && credential.Index != "" && account.AuthIndex == credential.Index && account.CredentialFingerprint != "" && account.CredentialFingerprint == AccessTokenSHA256(credential)
		observed, fresh := account.observation(snapshot, now)
		if !bound || account.Eligible == nil || len(account.Usage) == 0 || string(account.Usage) == "null" || observed.IsZero() || observed.After(now) {
			health.Missing++
		} else if !fresh || now.Sub(observed) >= 30*time.Minute {
			health.Stale++
		} else if now.Sub(observed) >= 10*time.Minute {
			health.Warning++
		} else {
			health.Fresh++
		}
		retry := snapshot.RetryState[credential.ID]
		if retry.AuthIndex == credential.Index && retry.CredentialFingerprint != "" && retry.CredentialFingerprint == AccessTokenSHA256(credential) {
			if reason := safeClaudeCollectorError(retry.LastError); reason != "" {
				health.Failing++
				if health.Errors == nil {
					health.Errors = make(map[string]int)
				}
				health.Errors[reason]++
			}
		}
		if snapshot.GlobalRetryAt.After(now) || retry.AuthIndex == credential.Index && retry.CredentialFingerprint != "" && retry.CredentialFingerprint == AccessTokenSHA256(credential) && retry.NextAttemptAt.After(now) {
			health.Backoff++
		}
	}
	if health.Total == 0 || health.Warning > 0 || health.Failing > 0 || health.Backoff > 0 || now.Sub(snapshot.ObservedAt) >= 10*time.Minute {
		health.Status = "degraded"
		health.Reason = "collector_refresh_delayed"
	}
	if health.Total == 0 {
		health.Reason = "no_claude_credentials"
	}
	if health.Stale > 0 || health.Missing > 0 || now.Sub(snapshot.ObservedAt) > 30*time.Minute {
		health.Status = "stale"
		health.Reason = "observations_unavailable"
	}
	if err != nil {
		health.Status = "stale"
		health.Reason = "snapshot_unavailable"
	}
	return health
}
