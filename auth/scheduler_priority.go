package auth

// 账号调度优先级（issue #358）：优先级高的账号严格先调度，同优先级内再按
// 健康档位与调度分竞争；账号不可用（冷却/暂停/限额）时自然回落到低优先级。
// 典型用法：官方账号设正值、API-Key 中转渠道保持默认或设负值，实现
// 「官方账号用尽才落中转」的兜底编排。
const (
	minSchedulerPriority int64 = -100
	maxSchedulerPriority int64 = 100
)

const (
	relayGuardianHintLastResortBit uint64 = 1
	relayGuardianHintHardCapShift         = 1
	relayGuardianHintHardCapMask   uint64 = (1 << 31) - 1
	relayGuardianHintPercentShift         = 32
	relayGuardianHintPercentMask   uint64 = (1 << 7) - 1
	relayGuardianHintVersionShift         = 39
	relayGuardianHintVersionMask   uint64 = (1 << 25) - 1
	relayGuardianHintPayloadMask   uint64 = (1 << relayGuardianHintVersionShift) - 1
)

// relayGuardianSchedulingHintSnapshot is the decoded in-memory scheduler overlay.
// lastResort affects ordering only. hardCap and percent independently constrain
// concurrency; when both are set, the smaller effective cap wins.
type relayGuardianSchedulingHintSnapshot struct {
	lastResort bool
	hardCap    int64
	percent    int
}

func normalizeSchedulerPriority(priority int64) int64 {
	switch {
	case priority < minSchedulerPriority:
		return minSchedulerPriority
	case priority > maxSchedulerPriority:
		return maxSchedulerPriority
	default:
		return priority
	}
}

func normalizeRelayGuardianHardCap(cap int64) int64 {
	if cap <= 0 {
		return 0
	}
	if uint64(cap) > relayGuardianHintHardCapMask {
		return int64(relayGuardianHintHardCapMask)
	}
	return cap
}

func normalizeRelayGuardianRecoveryPercent(percent int) int {
	if percent <= 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

func encodeRelayGuardianSchedulingHint(lastResort bool, hardCap int64, percent int) uint64 {
	var encoded uint64
	if lastResort {
		encoded |= relayGuardianHintLastResortBit
	}
	capValue := uint64(normalizeRelayGuardianHardCap(hardCap))
	encoded |= (capValue & relayGuardianHintHardCapMask) << relayGuardianHintHardCapShift
	percentValue := uint64(normalizeRelayGuardianRecoveryPercent(percent))
	encoded |= (percentValue & relayGuardianHintPercentMask) << relayGuardianHintPercentShift
	return encoded
}

func decodeRelayGuardianSchedulingHint(encoded uint64) relayGuardianSchedulingHintSnapshot {
	return relayGuardianSchedulingHintSnapshot{
		lastResort: encoded&relayGuardianHintLastResortBit != 0,
		hardCap:    int64((encoded >> relayGuardianHintHardCapShift) & relayGuardianHintHardCapMask),
		percent:    int((encoded >> relayGuardianHintPercentShift) & relayGuardianHintPercentMask),
	}
}

// setRelayGuardianSchedulingHint atomically replaces the runtime-only hint.
// It deliberately does not alter account configuration, enabled/Disabled, or
// any persisted scheduler fields.
func (a *Account) setRelayGuardianSchedulingHint(lastResort bool, hardCap int64, percent int) {
	if a == nil {
		return
	}
	payload := encodeRelayGuardianSchedulingHint(lastResort, hardCap, percent) & relayGuardianHintPayloadMask
	for {
		current := a.relayGuardianSchedulingHint.Load()
		if current&relayGuardianHintPayloadMask == payload {
			return
		}
		version := ((current >> relayGuardianHintVersionShift) + 1) & relayGuardianHintVersionMask
		next := payload | version<<relayGuardianHintVersionShift
		if a.relayGuardianSchedulingHint.CompareAndSwap(current, next) {
			return
		}
	}
}

func (a *Account) clearRelayGuardianSchedulingHint() {
	if a == nil {
		return
	}
	a.setRelayGuardianSchedulingHint(false, 0, 0)
}

// relayGuardianSchedulingToken returns one atomic value containing both the
// hint payload and its change version. FastScheduler uses it to reject a
// candidate if Guardian changes its class while group checks are in progress.
func (a *Account) relayGuardianSchedulingToken() uint64 {
	if a == nil {
		return 0
	}
	return a.relayGuardianSchedulingHint.Load()
}

func (a *Account) relayGuardianSchedulingHintSnapshot() relayGuardianSchedulingHintSnapshot {
	if a == nil {
		return relayGuardianSchedulingHintSnapshot{}
	}
	return decodeRelayGuardianSchedulingHint(a.relayGuardianSchedulingHint.Load())
}

func (a *Account) relayGuardianLastResort() bool {
	if a == nil {
		return false
	}
	return a.relayGuardianSchedulingHint.Load()&relayGuardianHintLastResortBit != 0
}

func relayGuardianConcurrencyLimitForToken(limit int64, token uint64) int64 {
	if limit <= 0 {
		return 0
	}
	hint := decodeRelayGuardianSchedulingHint(token)
	effective := limit
	if hint.hardCap > 0 && hint.hardCap < effective {
		effective = hint.hardCap
	}
	if hint.percent > 0 && hint.percent < 100 {
		// Round up and keep at least one recovery slot for small account limits.
		percent := int64(hint.percent)
		percentCap := (limit/100)*percent + ((limit%100)*percent+99)/100
		if percentCap < 1 {
			percentCap = 1
		}
		if percentCap < effective {
			effective = percentCap
		}
	}
	return effective
}

func (a *Account) relayGuardianConcurrencyLimit(limit int64) int64 {
	if a == nil {
		return 0
	}
	return relayGuardianConcurrencyLimitForToken(limit, a.relayGuardianSchedulingHint.Load())
}

func (a *Account) SetSchedulerPriority(priority int64) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.SchedulerPriority = normalizeSchedulerPriority(priority)
	a.mu.Unlock()
}

func (a *Account) schedulerPriority() int64 {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return normalizeSchedulerPriority(a.SchedulerPriority)
}

func (a *Account) GetSchedulerPriority() int64 {
	return a.schedulerPriority()
}

// ApplyAccountSchedulerPriority 动态更新账号调度优先级（nil 恢复默认 0）。
func (s *Store) ApplyAccountSchedulerPriority(dbID int64, priority *int64) bool {
	acc := s.FindByID(dbID)
	if acc == nil {
		return false
	}
	if priority == nil {
		acc.SetSchedulerPriority(0)
	} else {
		acc.SetSchedulerPriority(*priority)
	}
	s.fastSchedulerUpdate(acc)
	return true
}
