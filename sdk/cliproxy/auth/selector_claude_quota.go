package auth

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

type ClaudeQuotaSelector struct {
	SnapshotPath string
	Fallback     Selector

	// lastStaleWarnUnix rate-limits last-resort selection warnings.
	lastStaleWarnUnix atomic.Int64
}

type claudeQuotaAccount struct {
	ObservedAt            time.Time       `json:"observed_at,omitempty"`
	AuthIndex             string          `json:"auth_index,omitempty"`
	CredentialFingerprint string          `json:"credential_fingerprint,omitempty"`
	Usage                 json.RawMessage `json:"usage,omitempty"`
	WeeklyReset           time.Time       `json:"weekly_reset"`
	FiveHourReset         time.Time       `json:"five_hour_reset"`
	Eligible              *bool           `json:"eligible"`
	BlockedModelFamilies  []string        `json:"blocked_model_families"`
}

type claudeQuotaRetry struct {
	AuthIndex             string    `json:"auth_index"`
	CredentialFingerprint string    `json:"credential_fingerprint"`
	NextAttemptAt         time.Time `json:"next_attempt_at"`
	LastError             string    `json:"last_error,omitempty"`
}

type claudeQuotaSnapshot struct {
	RetryState    map[string]claudeQuotaRetry   `json:"retry_state,omitempty"`
	GlobalRetryAt time.Time                     `json:"global_retry_at,omitempty"`
	ObservedAt    time.Time                     `json:"observed_at"`
	Accounts      map[string]claudeQuotaAccount `json:"accounts"`
}

type claudeQuotaModelsKey struct{}

func sessionAffinitySelector(selector Selector) (*SessionAffinitySelector, bool) {
	if quota, ok := selector.(*ClaudeQuotaSelector); ok {
		selector = quota.Fallback
	}
	affinity, ok := selector.(*SessionAffinitySelector)
	return affinity, ok
}

func (selector *ClaudeQuotaSelector) OnResult(result Result) {
	if observer, ok := selector.Fallback.(interface{ OnResult(Result) }); ok {
		observer.OnResult(result)
	}
}

func (selector *ClaudeQuotaSelector) InvalidateAuth(authID string) {
	if invalidator, ok := selector.Fallback.(interface{ InvalidateAuth(string) }); ok {
		invalidator.InvalidateAuth(authID)
	}
}

func (selector *ClaudeQuotaSelector) LookupAffinity(provider, model, sessionID string, filters ...func(string) bool) (string, string) {
	if affinity, ok := sessionAffinitySelector(selector); ok {
		return affinity.LookupAffinity(provider, model, sessionID, filters...)
	}
	return "", "unsupported"
}

func (selector *ClaudeQuotaSelector) Stop() {
	if stoppable, ok := selector.Fallback.(StoppableSelector); ok {
		stoppable.Stop()
	}
}

func isClaudeQuotaAuth(candidate *Auth) bool {
	return candidate != nil && strings.EqualFold(candidate.Provider, "claude") && candidate.AuthKind() != AuthKindAPIKey
}

func hasClaudeQuotaAuth(auths []*Auth) bool {
	for _, candidate := range auths {
		if isClaudeQuotaAuth(candidate) {
			return true
		}
	}
	return false
}

type claudeQuotaCoolingKey struct{}

// claudeQuotaCoolingAuth is a Claude OAuth credential that the conductor
// removed from the selector's candidates because it is temporarily blocked
// (cooldown or transient unavailability) rather than permanently unusable.
type claudeQuotaCoolingAuth struct {
	auth  *Auth
	until time.Time
}

func (manager *Manager) claudeQuotaContext(ctx context.Context, selector Selector, model string, auths []*Auth, cooling []claudeQuotaCoolingAuth) context.Context {
	if _, ok := selector.(*ClaudeQuotaSelector); !ok {
		return ctx
	}
	models := make(map[string]string, len(auths)+len(cooling))
	for _, candidate := range auths {
		if isClaudeQuotaAuth(candidate) {
			models[candidate.ID] = manager.selectionModelForAuth(candidate, model)
		}
	}
	for _, entry := range cooling {
		if _, seen := models[entry.auth.ID]; !seen {
			models[entry.auth.ID] = manager.selectionModelForAuth(entry.auth, model)
		}
	}
	ctx = context.WithValue(ctx, claudeQuotaModelsKey{}, models)
	if len(cooling) > 0 {
		ctx = context.WithValue(ctx, claudeQuotaCoolingKey{}, cooling)
	}
	return ctx
}

// claudeQuotaCoolingAuths reports Claude OAuth candidates excluded from the
// available set only because of a timed block. Callers must hold m.mu.
func (manager *Manager) claudeQuotaCoolingAuths(selector Selector, candidates, available []*Auth, routeModel string, now time.Time) []claudeQuotaCoolingAuth {
	if _, ok := selector.(*ClaudeQuotaSelector); !ok {
		return nil
	}
	availableIDs := make(map[string]struct{}, len(available))
	for _, candidate := range available {
		if candidate != nil {
			availableIDs[candidate.ID] = struct{}{}
		}
	}
	var cooling []claudeQuotaCoolingAuth
	for _, candidate := range candidates {
		if !isClaudeQuotaAuth(candidate) {
			continue
		}
		if _, ok := availableIDs[candidate.ID]; ok {
			continue
		}
		blocked, reason, next := isAuthBlockedForModel(candidate, manager.selectionModelForAuth(candidate, routeModel), now)
		if !blocked || reason == blockReasonDisabled || !next.After(now) || hasUnauthorizedAuthFailure(candidate) {
			continue
		}
		cooling = append(cooling, claudeQuotaCoolingAuth{auth: candidate.Clone(), until: next})
	}
	return cooling
}

func (selector *ClaudeQuotaSelector) load(now time.Time) (claudeQuotaSnapshot, error) {
	invalid := newClaudeQuotaError("claude_quota_unavailable", "Claude quota snapshot is missing, invalid, or stale", "", now, time.Time{}, time.Time{})
	file, errOpen := os.Open(selector.SnapshotPath)
	if errOpen != nil {
		return claudeQuotaSnapshot{}, invalid
	}
	raw, errRead := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	errClose := file.Close()
	var snap claudeQuotaSnapshot
	if errRead != nil || errClose != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &snap) != nil || snap.Accounts == nil || snap.ObservedAt.IsZero() || snap.ObservedAt.After(now) {
		return claudeQuotaSnapshot{}, invalid
	}
	return snap, nil
}

func (account claudeQuotaAccount) observation(snapshot claudeQuotaSnapshot, now time.Time) (time.Time, bool) {
	observed := account.ObservedAt
	maxAge := 30 * time.Minute
	if observed.IsZero() {
		if account.AuthIndex != "" || len(account.Usage) > 0 || account.CredentialFingerprint != "" {
			return observed, false
		}
		observed = snapshot.ObservedAt
		maxAge = 2 * time.Minute
	}
	return observed, !observed.IsZero() && !observed.After(now) && now.Sub(observed) <= maxAge
}

func ReadClaudeQuotaUsage(path, authID, authIndex, fingerprint string, now time.Time) (json.RawMessage, time.Time, error) {
	snapshot, err := (&ClaudeQuotaSelector{SnapshotPath: path}).load(now)
	if err != nil {
		return nil, time.Time{}, err
	}
	account, exists := snapshot.Accounts[authID]
	observed, fresh := account.observation(snapshot, now)
	if !exists || !fresh || account.AuthIndex != authIndex || fingerprint == "" || account.CredentialFingerprint != fingerprint || len(account.Usage) == 0 || string(account.Usage) == "null" {
		return nil, time.Time{}, newClaudeQuotaError("claude_quota_unavailable", "Claude cached usage is unavailable", "", now, time.Time{}, snapshot.nextCheck(authID, authIndex, fingerprint, now))
	}
	return account.Usage, observed, nil
}

func (selector *ClaudeQuotaSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	return selector.pick(ctx, provider, model, opts, auths, time.Now())
}

type claudeQuotaState int

const (
	// claudeQuotaStateUnknown means no fresh, bound observation exists.
	claudeQuotaStateUnknown claudeQuotaState = iota
	// claudeQuotaStateStaleEligible means the latest bound observation is
	// stale but showed quota with a weekly reset still in the future.
	claudeQuotaStateStaleEligible
	// claudeQuotaStateRefresh means a fresh observation has expired windows.
	claudeQuotaStateRefresh
	// claudeQuotaStateBlocked means the account was observed without quota for the model.
	claudeQuotaStateBlocked
	// claudeQuotaStateEligible means a fresh, bound observation shows quota.
	claudeQuotaStateEligible
)

type claudeQuotaVerdict struct {
	state  claudeQuotaState
	data   claudeQuotaAccount
	reason string
}

// modelBlocked reports whether a blocked model family applies to model.
// Unresolvable models are treated as blocked whenever any family is blocked.
func (account claudeQuotaAccount) modelBlocked(model string) bool {
	resolved := strings.ToLower(model)
	knownFamily := false
	for _, family := range claudeQuotaFamilies {
		knownFamily = knownFamily || strings.Contains(resolved, family)
	}
	for _, family := range account.BlockedModelFamilies {
		if strings.TrimSpace(family) == "" || !knownFamily || strings.Contains(resolved, strings.ToLower(family)) {
			return true
		}
	}
	return false
}

// evaluate classifies one Claude credential against the snapshot. Stale
// eligibility is only granted to observations explicitly bound to the
// credential's current auth index and access-token fingerprint.
func (snapshot claudeQuotaSnapshot) evaluate(candidate *Auth, model string, now time.Time) claudeQuotaVerdict {
	fingerprint := AccessTokenSHA256(candidate)
	data, known := snapshot.Accounts[candidate.ID]
	_, fresh := data.observation(snapshot, now)
	legacy := data.ObservedAt.IsZero() && data.AuthIndex == "" && len(data.Usage) == 0 && data.CredentialFingerprint == ""
	explicit := data.AuthIndex != "" && data.AuthIndex == candidate.Index && data.CredentialFingerprint != "" && data.CredentialFingerprint == fingerprint
	bound := legacy || explicit
	verdict := claudeQuotaVerdict{state: claudeQuotaStateUnknown, data: data, reason: "observation_unavailable"}
	if !known || data.Eligible == nil || !fresh || !bound {
		if retry := snapshot.RetryState[candidate.ID]; retry.AuthIndex == candidate.Index && retry.CredentialFingerprint == fingerprint && safeClaudeCollectorError(retry.LastError) != "" {
			verdict.reason = "collector_refresh_failed"
		} else if known && bound && !fresh {
			verdict.reason = "observation_stale"
		}
		if known && explicit && !fresh && data.Eligible != nil && *data.Eligible && !data.ObservedAt.IsZero() && !data.ObservedAt.After(now) && data.WeeklyReset.After(now) && !data.modelBlocked(model) {
			verdict.state = claudeQuotaStateStaleEligible
		}
		return verdict
	}
	verdict.reason = ""
	if !*data.Eligible {
		verdict.state = claudeQuotaStateBlocked
		return verdict
	}
	if data.WeeklyReset.IsZero() || !data.WeeklyReset.After(now) || data.FiveHourReset.IsZero() || !data.FiveHourReset.After(now) {
		verdict.state = claudeQuotaStateRefresh
		return verdict
	}
	if data.modelBlocked(model) {
		verdict.state = claudeQuotaStateBlocked
		return verdict
	}
	verdict.state = claudeQuotaStateEligible
	return verdict
}

// claudeQuotaPreferred orders accounts by earliest weekly reset, then earliest
// five-hour reset, then ID.
func claudeQuotaPreferred(candidate *Auth, data claudeQuotaAccount, best *Auth, bestData claudeQuotaAccount) bool {
	if best == nil || data.WeeklyReset.Before(bestData.WeeklyReset) {
		return true
	}
	if !data.WeeklyReset.Equal(bestData.WeeklyReset) {
		return false
	}
	if data.FiveHourReset.Before(bestData.FiveHourReset) {
		return true
	}
	return data.FiveHourReset.Equal(bestData.FiveHourReset) && candidate.ID < best.ID
}

// coolingEligibleUntil returns the earliest cooldown end among credentials that
// the conductor excluded only temporarily but that still have quota in the
// snapshot. Such a request is retryable soon and must not be reported as
// quota exhaustion.
func (snapshot claudeQuotaSnapshot) coolingEligibleUntil(ctx context.Context, model string, models map[string]string, weighted bool, now time.Time) (time.Time, bool) {
	cooling, _ := ctx.Value(claudeQuotaCoolingKey{}).([]claudeQuotaCoolingAuth)
	var earliest time.Time
	for _, entry := range cooling {
		if entry.auth == nil || !isClaudeQuotaAuth(entry.auth) || !entry.until.After(now) {
			continue
		}
		if weighted && authWeight(entry.auth) <= 0 {
			continue
		}
		resolved := models[entry.auth.ID]
		if resolved == "" {
			resolved = model
		}
		switch snapshot.evaluate(entry.auth, resolved, now).state {
		case claudeQuotaStateEligible, claudeQuotaStateStaleEligible:
			if earliest.IsZero() || entry.until.Before(earliest) {
				earliest = entry.until
			}
		}
	}
	return earliest, !earliest.IsZero()
}

func (selector *ClaudeQuotaSelector) pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth, now time.Time) (*Auth, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	fallback := selector.Fallback
	if fallback == nil {
		fallback = &RoundRobinSelector{}
	}
	if !hasClaudeQuotaAuth(auths) {
		return fallback.Pick(ctx, provider, model, opts, auths)
	}
	snap, quotaErr := selector.load(now)
	var accountErr error
	var earliestReset, earliestNextCheck time.Time
	unknownReset := false
	unavailableReason := "observation_unavailable"
	weightSelector := fallback
	if affinity, ok := sessionAffinitySelector(fallback); ok {
		weightSelector = affinity.fallback
	}
	_, weighted := weightSelector.(*WeightedRoundRobinSelector)
	models, _ := ctx.Value(claudeQuotaModelsKey{}).(map[string]string)
	var best, stale *Auth
	var bestData, staleData claudeQuotaAccount
	for _, candidate := range auths {
		if !isClaudeQuotaAuth(candidate) {
			continue
		}
		if weighted && authWeight(candidate) <= 0 {
			continue
		}
		nextCheck := snap.nextCheck(candidate.ID, candidate.Index, AccessTokenSHA256(candidate), now)
		if earliestNextCheck.IsZero() || nextCheck.Before(earliestNextCheck) {
			earliestNextCheck = nextCheck
		}
		resolved := models[candidate.ID]
		if resolved == "" {
			resolved = model
		}
		verdict := snap.evaluate(candidate, resolved, now)
		switch verdict.state {
		case claudeQuotaStateUnknown, claudeQuotaStateStaleEligible:
			accountErr = &Error{Code: "claude_quota_unavailable", Message: "Claude candidate quota is unknown", HTTPStatus: 503}
			if verdict.reason == "collector_refresh_failed" {
				unavailableReason = verdict.reason
			} else if unavailableReason != "collector_refresh_failed" && verdict.reason == "observation_stale" {
				unavailableReason = verdict.reason
			}
			if verdict.state == claudeQuotaStateStaleEligible && claudeQuotaPreferred(candidate, verdict.data, stale, staleData) {
				stale, staleData = candidate, verdict.data
			}
		case claudeQuotaStateRefresh:
			accountErr = &Error{Code: "claude_quota_unavailable", Message: "Claude quota windows need refreshing", HTTPStatus: 503}
		case claudeQuotaStateBlocked:
			reset := verdict.data.blockingReset(resolved, now)
			if reset.IsZero() {
				unknownReset = true
			} else if earliestReset.IsZero() || reset.Before(earliestReset) {
				earliestReset = reset
			}
		case claudeQuotaStateEligible:
			if claudeQuotaPreferred(candidate, verdict.data, best, bestData) {
				best, bestData = candidate, verdict.data
			}
		}
	}
	// Fresh eligibility always wins. A stale-but-eligible observation is only
	// a last resort so a stalled collector does not refuse every request.
	chosen := best
	if chosen == nil && stale != nil {
		chosen = stale
		if last := selector.lastStaleWarnUnix.Load(); now.Unix()-last >= 60 && selector.lastStaleWarnUnix.CompareAndSwap(last, now.Unix()) {
			log.Warnf("claude quota: no fresh eligible account; using last-resort account %s observed at %s (weekly reset %s)", stale.ID, staleData.ObservedAt.UTC().Format(time.RFC3339), staleData.WeeklyReset.UTC().Format(time.RFC3339))
		}
	}
	pool := make([]*Auth, 0, len(auths))
	for _, candidate := range auths {
		if !isClaudeQuotaAuth(candidate) {
			pool = append(pool, candidate)
		}
	}
	if quotaErr == nil && chosen != nil {
		pool = append(pool, chosen)
	}
	if len(pool) == 0 {
		if quotaErr != nil {
			err := newClaudeQuotaError("claude_quota_unavailable", "Claude quota snapshot is unavailable; check the quota collector", model, now, time.Time{}, earliestNextCheck)
			err.Reason = "snapshot_unavailable"
			return nil, err
		}
		if until, ok := snap.coolingEligibleUntil(ctx, model, models, weighted, now); ok {
			err := newClaudeQuotaError("claude_quota_unavailable", "A Claude account with quota is temporarily cooling down after an upstream error; retry shortly", model, now, time.Time{}, until)
			err.Reason = "eligible_account_cooling"
			return nil, err
		}
		if accountErr != nil {
			message := "Claude quota observations are unavailable; check the quota collector"
			if unavailableReason == "collector_refresh_failed" {
				message = "Claude quota refresh failed and cached observations are unavailable; check collector health"
			} else if unavailableReason == "observation_stale" {
				message = "Claude quota observations expired; check the quota collector"
			}
			err := newClaudeQuotaError("claude_quota_unavailable", message, model, now, time.Time{}, earliestNextCheck)
			err.Reason = unavailableReason
			return nil, err
		}
		if unknownReset {
			earliestReset = time.Time{}
		}
		return nil, newClaudeQuotaError("claude_quota_exhausted", "No Claude account has quota for this model", model, now, earliestReset, earliestNextCheck)
	}
	sort.Slice(pool, func(first, second int) bool { return pool[first].ID < pool[second].ID })
	selected, errPick := fallback.Pick(ctx, provider, model, opts, pool)
	if errPick != nil {
		return nil, errPick
	}
	if isClaudeQuotaAuth(selected) {
		return chosen, nil
	}
	return selected, nil
}

// nextCheck respects collector backoff only when it belongs to the current
// credential. A global collector pause applies regardless of account binding.
func (snapshot claudeQuotaSnapshot) nextCheck(authID, authIndex, fingerprint string, now time.Time) time.Time {
	next := now.Add(time.Minute)
	retry := snapshot.RetryState[authID]
	if authIndex != "" && fingerprint != "" && retry.AuthIndex == authIndex && retry.CredentialFingerprint == fingerprint && retry.NextAttemptAt.After(now) {
		next = retry.NextAttemptAt
	}
	if snapshot.GlobalRetryAt.After(next) {
		next = snapshot.GlobalRetryAt
	}
	return next
}
