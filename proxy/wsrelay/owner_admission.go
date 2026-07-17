package wsrelay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
)

const (
	safePoolOwnerSampleBPSEnv        = "CODEX_WS_SAFE_POOL_OWNER_SAMPLE_BPS"
	safePoolOwnerBudgetPerAccountEnv = "CODEX_WS_SAFE_POOL_OWNER_BUDGET_PER_ACCOUNT"

	maximumSafePoolOwnerSampleBPS = 10000
	maximumSafePoolOwnerBudget    = 10000
	safePoolOwnerSampleDomain     = "codex2api/ws-safe-owner-sample/v1"
)

type safePoolOwnerAdmissionConfig struct {
	sampleBPS int
	budget    int
	valid     bool
}

// ownerAdmissionIntegerFromEnv is deliberately fail-closed. A missing,
// malformed, negative, or oversized owner guard must never widen a canary.
func ownerAdmissionIntegerFromEnv(name string, maximum int) (int, bool) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 || value > maximum {
		return 0, false
	}
	return value, true
}

func currentSafePoolOwnerAdmissionConfig() safePoolOwnerAdmissionConfig {
	sampleBPS, sampleValid := ownerAdmissionIntegerFromEnv(safePoolOwnerSampleBPSEnv, maximumSafePoolOwnerSampleBPS)
	budget, budgetValid := ownerAdmissionIntegerFromEnv(safePoolOwnerBudgetPerAccountEnv, maximumSafePoolOwnerBudget)
	return safePoolOwnerAdmissionConfig{
		sampleBPS: sampleBPS,
		budget:    budget,
		valid:     sampleValid && budgetValid,
	}
}

func newSafePoolOwnerSampleSalt() ([sha256.Size]byte, bool) {
	var salt [sha256.Size]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return [sha256.Size]byte{}, false
	}
	return salt, true
}

// safePoolOwnerSampled is deterministic only for one Manager lifetime. The
// process-local random salt prevents a caller that controls session/thread IDs
// from enumerating an admitted owner offline. accountID is a dynamic runtime
// bucket, never a configured or compiled account allowlist.
func (m *Manager) safePoolOwnerSampled(accountID int64, ownerKey string, sampleBPS int) bool {
	ownerKey = strings.TrimSpace(ownerKey)
	if m == nil || !m.ownerAdmissionSaltValid || accountID <= 0 || ownerKey == "" || sampleBPS <= 0 {
		return false
	}
	if sampleBPS >= maximumSafePoolOwnerSampleBPS {
		return true
	}
	hash := hmac.New(sha256.New, m.ownerAdmissionSalt[:])
	hash.Write([]byte(safePoolOwnerSampleDomain))
	hash.Write([]byte{0})
	var accountBytes [8]byte
	binary.BigEndian.PutUint64(accountBytes[:], uint64(accountID))
	hash.Write(accountBytes[:])
	hash.Write([]byte{0})
	hash.Write([]byte(ownerKey))
	sum := hash.Sum(nil)
	bucket := binary.BigEndian.Uint64(sum[:8]) % maximumSafePoolOwnerSampleBPS
	return bucket < uint64(sampleBPS)
}

type safePoolOwnerAdmissionDecision uint8

const (
	safePoolOwnerRejectedBySample safePoolOwnerAdmissionDecision = iota
	safePoolOwnerRejectedByBudget
	safePoolOwnerRejectedByLifecycle
	safePoolOwnerAdmittedNew
	safePoolOwnerAdmittedExisting
)

func (decision safePoolOwnerAdmissionDecision) admitted() bool {
	return decision == safePoolOwnerAdmittedNew || decision == safePoolOwnerAdmittedExisting
}

// admitSafePoolOwner is the process-lifetime blast-radius guard. Existing
// owners are checked before the current sample/budget, so hot tightening never
// revokes an admitted owner or its connection-local continuation. Retire and
// account tag changes deliberately do not clear this registry.
func (m *Manager) admitSafePoolOwner(accountID int64, ownerKey string, config safePoolOwnerAdmissionConfig) safePoolOwnerAdmissionDecision {
	ownerKey = strings.TrimSpace(ownerKey)
	if m == nil || accountID <= 0 || ownerKey == "" {
		return safePoolOwnerRejectedBySample
	}
	// Admission participates in the same Manager lifecycle as socket acquire.
	// Stop closes the operation gate, waits for any already-admitted commit,
	// and only then clears the registry. No owner can be written back after the
	// process-lifetime registry has reached its terminal empty state.
	_, finishOperation, err := m.beginOperation(context.Background())
	if err != nil {
		return safePoolOwnerRejectedByLifecycle
	}
	defer finishOperation()
	if m.beforeOwnerAdmissionCommit != nil {
		m.beforeOwnerAdmissionCommit()
	}

	m.ownerAdmissionMu.Lock()
	defer m.ownerAdmissionMu.Unlock()

	owners := m.safePoolAdmittedOwners[accountID]
	if _, exists := owners[ownerKey]; exists {
		m.safePoolOwnerAdmittedExisting.Add(1)
		return safePoolOwnerAdmittedExisting
	}
	if !config.valid || !m.ownerAdmissionSaltValid {
		m.safePoolOwnerConfigErrors.Add(1)
	}
	if !config.valid || !m.safePoolOwnerSampled(accountID, ownerKey, config.sampleBPS) {
		m.safePoolOwnerSampleRejected.Add(1)
		m.safePoolOwnerOneShotFallbacks.Add(1)
		return safePoolOwnerRejectedBySample
	}
	if config.budget <= 0 || len(owners) >= config.budget {
		m.safePoolOwnerBudgetRejected.Add(1)
		m.safePoolOwnerOneShotFallbacks.Add(1)
		return safePoolOwnerRejectedByBudget
	}
	if owners == nil {
		if m.safePoolAdmittedOwners == nil {
			m.safePoolAdmittedOwners = make(map[int64]map[string]struct{})
		}
		owners = make(map[string]struct{})
		m.safePoolAdmittedOwners[accountID] = owners
	}
	owners[ownerKey] = struct{}{}
	m.safePoolOwnerAdmittedNew.Add(1)
	return safePoolOwnerAdmittedNew
}

func (m *Manager) safePoolOwnerAdmissionSnapshot(budget int) (owners int, accounts int, overcommittedAccounts int) {
	if m == nil {
		return 0, 0, 0
	}
	m.ownerAdmissionMu.Lock()
	defer m.ownerAdmissionMu.Unlock()
	for _, admitted := range m.safePoolAdmittedOwners {
		if len(admitted) == 0 {
			continue
		}
		accounts++
		owners += len(admitted)
		if len(admitted) > budget {
			overcommittedAccounts++
		}
	}
	return owners, accounts, overcommittedAccounts
}
