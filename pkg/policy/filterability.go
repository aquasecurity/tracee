package policy

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// perRuleKernelScopeDim are the scope dimensions the kernel can filter when they come from a rule's
// `filters:` list (comm/uid/pid/mntns/pidns/executable via processRuleScopeFilters map writes, container
// via computeScopeFiltersConfig). Other dims (uts, tree, ...) from a per-rule scope stay in user space.
var perRuleKernelScopeDim = map[string]bool{
	"comm": true, "uid": true, "pid": true, "mntns": true, "pidns": true, "container": true, "executable": true,
}

// RuleFilterInfo is a read-only, per-rule filterability summary for `tracee list filterable`. It records
// where each of a rule's filters is enforced: KERNEL (dropped before the event is submitted) vs USER
// SPACE (the event is submitted, then filtered). The four buckets mirror the real code paths:
//   - KernelScope: policy spec.scope + detector scope_filters (processRuleScopeFilters -> kernel maps)
//   - KernelData:  a pathname data filter (the one kernel-capable data field)
//   - UserScope:   per-rule scope filters (rule `filters:` list) - applied only in matchPolicies today
//   - UserData:    non-pathname data filters and return-value filters
type RuleFilterInfo struct {
	Policy      string
	Bootstrap   bool
	Dependency  bool
	KernelScope []string
	KernelData  []string
	UserScope   []string
	UserData    []string
}

// KernelNarrows reports whether this rule contributes any kernel-side narrowing.
func (r RuleFilterInfo) KernelNarrows() bool { return len(r.KernelScope) > 0 || len(r.KernelData) > 0 }

// UserNarrows reports whether this rule contributes any user-space narrowing.
func (r RuleFilterInfo) UserNarrows() bool { return len(r.UserScope) > 0 || len(r.UserData) > 0 }

// EventFilterInfo is the per-event roll-up of its rules.
type EventFilterInfo struct {
	Event     events.ID
	EventName string
	Rules     []RuleFilterInfo
}

// GetFilterabilityByEvent returns, per selected non-internal event, the filterability summary of every
// rule on it (user, dependency, and bootstrap) computed from the real rule set - so it reflects
// dependency expansion (derived/detector base events) and the kernel-submission union exactly. Read-only.
func (pm *PolicyManager) GetFilterabilityByEvent() []EventFilterInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	out := make([]EventFilterInfo, 0, len(pm.rules))
	for eid, er := range pm.rules {
		def := events.Core.GetDefinitionByID(eid)
		// Skip internal events and signature/detector outputs: those are produced in user space, so the
		// "kernel vs user-space filtering" question does not apply to them. Their kernel base events are
		// still reported (they enter pm.rules as dependencies).
		if def.IsInternal() || def.IsSignature() || def.IsDetector() {
			continue
		}
		efi := EventFilterInfo{Event: eid, EventName: def.GetName()}
		for _, rule := range er.Rules {
			efi.Rules = append(efi.Rules, classifyRule(rule))
		}
		out = append(out, efi)
	}
	return out
}

type enabledDim struct {
	on   bool
	name string
}

func dims(ds ...enabledDim) []string {
	var out []string
	for _, d := range ds {
		if d.on {
			out = append(out, d.name)
		}
	}
	return out
}

func hasPathnameFilter(df *filters.DataFilter) bool {
	if df == nil || !df.Enabled() {
		return false
	}
	_, err := df.Equalities()
	return err == nil
}

// scopeFilterDims lists the enumerable enabled dimensions of a per-rule scope filter (the ones the
// kernel could represent if per-rule scope pushdown existed). Falls back to a generic label.
func scopeFilterDims(sf *filters.ScopeFilter) []string {
	d := dims(
		enabledDim{sf.Comm().Enabled(), "comm"},
		enabledDim{sf.UID().Enabled(), "uid"},
		enabledDim{sf.PID().Enabled(), "pid"},
		enabledDim{sf.MntNS().Enabled(), "mntns"},
		enabledDim{sf.PidNS().Enabled(), "pidns"},
		enabledDim{sf.Container().Enabled(), "container"},
		enabledDim{sf.Binary().Enabled(), "executable"},
	)
	if len(d) == 0 {
		d = []string{"scope"}
	}
	return d
}

func classifyRule(rule *EventRule) RuleFilterInfo {
	info := RuleFilterInfo{
		Bootstrap:  rule.SelectionType == SelectedByBootstrap,
		Dependency: rule.IsDependency(),
	}
	if rule.Policy != nil {
		info.Policy = rule.Policy.Name
	}

	// Kernel scope: policy-level scope + detector scope (processRuleScopeFilters writes these to the
	// kernel maps; for a dependency rule the policy scope is shared and propagates down the chain).
	if p := rule.Policy; p != nil {
		info.KernelScope = append(info.KernelScope, dims(
			enabledDim{p.CommFilter.Enabled(), "comm"},
			enabledDim{p.UIDFilter.Enabled(), "uid"},
			enabledDim{p.PIDFilter.Enabled(), "pid"},
			enabledDim{p.MntNSFilter.Enabled(), "mntns"},
			enabledDim{p.PidNSFilter.Enabled(), "pidns"},
			enabledDim{p.UTSFilter.Enabled(), "uts"},
			enabledDim{p.ContFilter.Enabled() || p.ContIDFilter.Enabled() || p.NewContFilter.Enabled(), "container"},
			enabledDim{p.ProcessTreeFilter.Enabled(), "tree"},
			enabledDim{p.BinaryFilter.Enabled(), "executable"},
		)...)
	}
	if ds := rule.DetectorScopeFilter; ds != nil && ds.Enabled() {
		for _, d := range scopeFilterDims(ds) {
			info.KernelScope = append(info.KernelScope, d+" (detector)")
		}
	}

	// Kernel data: a pathname filter. DetectorDataFilter is on the base schema (applies to every rule);
	// Data.DataFilter belongs to the consumer, so it only narrows a directly-selected (non-dep) rule.
	if hasPathnameFilter(rule.DetectorDataFilter) {
		info.KernelData = append(info.KernelData, "pathname (detector)")
	}
	if rule.Data != nil && !rule.IsDependency() {
		if df := rule.Data.DataFilter; df != nil && df.Enabled() {
			if hasPathnameFilter(df) {
				info.KernelData = append(info.KernelData, "pathname")
			} else {
				info.UserData = append(info.UserData, "data")
			}
		}
	}

	// Per-rule scope (rule `filters:`, rule.Data.ScopeFilter). Kernel-pushable dims (comm/uid/pid/mntns/
	// pidns) are pushed to the kernel unless the policy or detector already covers that dimension (see
	// processRuleScopeFilters); other dims stay user-space.
	if perRule := ruleDataScope(rule); perRule != nil && perRule.Enabled() {
		covered := make(map[string]bool, len(info.KernelScope))
		for _, k := range info.KernelScope {
			covered[strings.TrimSuffix(k, " (detector)")] = true
		}
		for _, d := range scopeFilterDims(perRule) {
			if perRuleKernelScopeDim[d] && !covered[d] {
				info.KernelScope = append(info.KernelScope, d+" (rule)")
			} else {
				info.UserScope = append(info.UserScope, d)
			}
		}
	}

	// User-space return-value filter (directly-selected rules only).
	if rule.Data != nil && !rule.IsDependency() && rule.Data.RetFilter != nil && rule.Data.RetFilter.Enabled() {
		info.UserData = append(info.UserData, "retval")
	}

	return info
}
