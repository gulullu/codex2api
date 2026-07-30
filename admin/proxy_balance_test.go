package admin

import "testing"

// 未绑定账号按最少负载均匀摊开,并列时取 URL 字典序保证确定性。
func TestComputeProxyAssignmentsSpreadsEvenly(t *testing.T) {
	targets := []balanceAccount{{id: 1}, {id: 2}, {id: 3}, {id: 4}, {id: 5}, {id: 6}}
	candidates := []string{"http://p1", "http://p2", "http://p3"}

	result := computeProxyAssignments(targets, candidates, nil, 0)

	if len(result.assignments) != 6 || result.kept != 0 || result.skipped != 0 {
		t.Fatalf("assignments=%d kept=%d skipped=%d, want 6/0/0", len(result.assignments), result.kept, result.skipped)
	}
	for _, url := range candidates {
		if result.load[url] != 2 {
			t.Fatalf("load[%s] = %d, want 2 (result: %+v)", url, result.load[url], result.load)
		}
	}
	// 确定性:ID 升序 × URL 字典序 → 1→p1 2→p2 3→p3 4→p1 ...
	if result.assignments[1] != "http://p1" || result.assignments[2] != "http://p2" || result.assignments[4] != "http://p1" {
		t.Fatalf("assignment order not deterministic: %+v", result.assignments)
	}
}

// 基线负载(其它渠道的既有绑定)计入,新账号先填空闲代理。
func TestComputeProxyAssignmentsRespectsBaseline(t *testing.T) {
	targets := []balanceAccount{{id: 10}, {id: 11}}
	candidates := []string{"http://busy", "http://idle"}
	baseline := map[string]int64{"http://busy": 5}

	result := computeProxyAssignments(targets, candidates, baseline, 0)

	if result.assignments[10] != "http://idle" || result.assignments[11] != "http://idle" {
		t.Fatalf("accounts should land on idle proxy first: %+v", result.assignments)
	}
	if result.load["http://idle"] != 2 || result.load["http://busy"] != 5 {
		t.Fatalf("load = %+v, want idle=2 busy=5", result.load)
	}
}

// all 模式:仍在候选池且未超上限的现有绑定保持不动(减少换 IP),失效绑定被重排。
func TestComputeProxyAssignmentsKeepsValidBindings(t *testing.T) {
	targets := []balanceAccount{
		{id: 1, current: "http://p1"},   // 有效绑定 → 保持
		{id: 2, current: "http://dead"}, // 绑定不在候选池 → 重排
		{id: 3},                         // 未绑定 → 分配
	}
	candidates := []string{"http://p1", "http://p2"}

	result := computeProxyAssignments(targets, candidates, nil, 0)

	if result.kept != 1 {
		t.Fatalf("kept = %d, want 1", result.kept)
	}
	if _, ok := result.assignments[1]; ok {
		t.Fatalf("account 1 should keep its binding, got reassigned: %+v", result.assignments)
	}
	if result.assignments[2] != "http://p2" {
		t.Fatalf("account 2 should move to least-loaded p2, got %q", result.assignments[2])
	}
	// 账号 3 分配时 p1/p2 均为 1,并列取字典序 → p1。
	if result.assignments[3] != "http://p1" {
		t.Fatalf("account 3 tie-break should pick p1, got %q", result.assignments[3])
	}
	if result.load["http://p1"] != 2 || result.load["http://p2"] != 1 {
		t.Fatalf("load = %+v, want p1=2 p2=1", result.load)
	}
}

// 每代理上限:超出容量的账号计入 skipped,不强塞。
func TestComputeProxyAssignmentsHonorsCap(t *testing.T) {
	targets := []balanceAccount{{id: 1}, {id: 2}, {id: 3}, {id: 4}, {id: 5}}
	candidates := []string{"http://p1", "http://p2"}

	result := computeProxyAssignments(targets, candidates, nil, 2)

	if len(result.assignments) != 4 || result.skipped != 1 {
		t.Fatalf("assignments=%d skipped=%d, want 4/1", len(result.assignments), result.skipped)
	}
	if result.load["http://p1"] != 2 || result.load["http://p2"] != 2 {
		t.Fatalf("load = %+v, want both at cap 2", result.load)
	}
}

// 上限也约束"保持现有绑定":已超上限的代理上的存量绑定会被挪走。
func TestComputeProxyAssignmentsCapEvictsOverloadedKeep(t *testing.T) {
	targets := []balanceAccount{
		{id: 1, current: "http://p1"},
		{id: 2, current: "http://p1"},
		{id: 3, current: "http://p1"},
	}
	candidates := []string{"http://p1", "http://p2"}

	result := computeProxyAssignments(targets, candidates, nil, 2)

	if result.kept != 2 {
		t.Fatalf("kept = %d, want 2 (cap keeps first two on p1)", result.kept)
	}
	if result.assignments[3] != "http://p2" {
		t.Fatalf("account 3 should overflow to p2, got %+v", result.assignments)
	}
}
