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
// owners in the current rollout generation are checked before the current
// sample/budget, so hot tightening does not revoke them. A policy/tag retire
// invalidates that generation and deliberately clears its owner registry.
func (m *Manager) admitSafePoolOwner(accountID int64, ownerKey string, config safePoolOwnerAdmissionConfig) (safePoolOwnerAdmissionDecision, uint64) {
	ownerKey = strings.TrimSpace(ownerKey)
	if m == nil || accountID <= 0 || ownerKey == "" {
		return safePoolOwnerRejectedBySample, 0
	}
	// Admission participates in the same Manager lifecycle as socket acquire.
	// Stop closes the operation gate, waits for any already-admitted commit,
	// and only then clears the registry. No owner can be written back after the
	// process-lifetime registry has reached its terminal empty state.
	_, finishOperation, err := m.beginOperation(context.Background())
	if err != nil {
		return safePoolOwnerRejectedByLifecycle, 0
	}
	defer finishOperation()
	if m.beforeOwnerAdmissionCommit != nil {
		m.beforeOwnerAdmissionCommit()
	}

	m.ownerAdmissionMu.Lock()
	defer m.ownerAdmissionMu.Unlock()

	generation := m.safePoolAccountGenerations[accountID]
	if generation == 0 {
		if m.safePoolAccountGenerations == nil {
			m.safePoolAccountGenerations = make(map[int64]uint64)
		}
		generation = 1
		m.safePoolAccountGenerations[accountID] = generation
	}
	owners := m.safePoolAdmittedOwners[accountID]
	if ownerGeneration, exists := owners[ownerKey]; exists && ownerGeneration == generation {
		m.safePoolOwnerAdmittedExisting.Add(1)
		return safePoolOwnerAdmittedExisting, generation
	}
	if !config.valid || !m.ownerAdmissionSaltValid {
		m.safePoolOwnerConfigErrors.Add(1)
	}
	if !config.valid || !m.safePoolOwnerSampled(accountID, ownerKey, config.sampleBPS) {
		m.safePoolOwnerSampleRejected.Add(1)
		m.safePoolOwnerOneShotFallbacks.Add(1)
		return safePoolOwnerRejectedBySample, 0
	}
	if config.budget <= 0 || len(owners) >= config.budget {
		m.safePoolOwnerBudgetRejected.Add(1)
		m.safePoolOwnerOneShotFallbacks.Add(1)
		return safePoolOwnerRejectedByBudget, 0
	}
	if owners == nil {
		if m.safePoolAdmittedOwners == nil {
			m.safePoolAdmittedOwners = make(map[int64]map[string]uint64)
		}
		owners = make(map[string]uint64)
		m.safePoolAdmittedOwners[accountID] = owners
	}
	owners[ownerKey] = generation
	// Track the account at the admission commit, not only after a socket dial.
	// Retire must be able to invalidate an admitted owner even when no physical
	// socket was ever created (for example, a tag removal racing a cold dial).
	m.safePoolAccounts.Store(accountID, struct{}{})
	m.safePoolOwnerAdmittedNew.Add(1)
	return safePoolOwnerAdmittedNew, generation
}

func (m *Manager) safePoolOwnerGeneration(accountID int64, ownerKey string) (uint64, bool) {
	ownerKey = strings.TrimSpace(ownerKey)
	if m == nil || accountID <= 0 || ownerKey == "" {
		return 0, false
	}
	m.ownerAdmissionMu.Lock()
	defer m.ownerAdmissionMu.Unlock()
	return m.safePoolOwnerGenerationLocked(accountID, ownerKey)
}

func (m *Manager) safePoolOwnerGenerationLocked(accountID int64, ownerKey string) (uint64, bool) {
	generation := m.safePoolAccountGenerations[accountID]
	if generation == 0 {
		return 0, false
	}
	ownerGeneration, exists := m.safePoolAdmittedOwners[accountID][ownerKey]
	return generation, exists && ownerGeneration == generation
}

func (m *Manager) safePoolIdentityGenerationCurrent(accountID int64, identity safeConnectionIdentity) bool {
	if m == nil || !identity.valid() || accountID <= 0 {
		return false
	}
	m.ownerAdmissionMu.Lock()
	defer m.ownerAdmissionMu.Unlock()
	return m.safePoolIdentityGenerationCurrentLocked(accountID, identity)
}

func (m *Manager) safePoolIdentityGenerationCurrentLocked(accountID int64, identity safeConnectionIdentity) bool {
	generation, ok := m.safePoolOwnerGenerationLocked(accountID, identity.ownerKey)
	return ok && identity.generation == generation
}

// invalidateSafePoolGenerationLocked is the linearization point for a master
// tag removal or force-fuse. Caller holds ownerAdmissionMu. Every invalidation
// advances the account-local generation and clears all admitted owners, even
// when the old generation never reached socket creation.
func (m *Manager) invalidateSafePoolGenerationLocked(accountID int64) int {
	retiredOwners := len(m.safePoolAdmittedOwners[accountID])
	if m.safePoolAccountGenerations == nil {
		m.safePoolAccountGenerations = make(map[int64]uint64)
	}
	next := m.safePoolAccountGenerations[accountID] + 1
	if next == 0 {
		// A process cannot realistically exhaust uint64 generations. Fail closed
		// on wrap instead of making an old generation current again.
		next = ^uint64(0)
	}
	m.safePoolAccountGenerations[accountID] = next
	delete(m.safePoolAdmittedOwners, accountID)
	m.safePoolAccounts.Delete(accountID)
	m.safePoolGenerationInvalidations.Add(1)
	if retiredOwners > 0 {
		m.safePoolRetiredOwners.Add(uint64(retiredOwners))
	}
	return retiredOwners
}

func (m *Manager) safePoolAccountHasAdmittedOwners(accountID int64) bool {
	if m == nil || accountID <= 0 {
		return false
	}
	m.ownerAdmissionMu.Lock()
	defer m.ownerAdmissionMu.Unlock()
	return len(m.safePoolAdmittedOwners[accountID]) > 0
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
