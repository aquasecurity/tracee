package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/datastores"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/policy"
	policyv1beta1 "github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

// kernelScopeDims are the workload-level scope filter dimensions Tracee pushes into the kernel. They act
// on an event's own workload context and drop non-matching instances before submission. tree/follow only
// cover an event's first 64 rules (see the overflow note in the printed output).
var kernelScopeDims = []string{
	"comm", "uid", "pid", "mntns", "pidns", "uts", "cgroupId", "container", "tree", "executable",
}

// EventFilterability describes where each of an event's filters is enforced (kernel vs user space).
type EventFilterability struct {
	Event         string   `json:"event"`
	KernelScope   []string `json:"kernel_scope"`            // workload scope dims (always kernel)
	KernelData    []string `json:"kernel_data"`             // data fields filtered in the kernel (pathname-class)
	UserSpaceData []string `json:"user_space_data"`         // data fields filtered only in user space
	ReturnValue   bool     `json:"return_value_user_space"` // a retval filter is user-space only
}

// PrintFilterableFields prints, for each named event, which fields Tracee can filter in the kernel versus
// which force user-space filtering. Output goes to stdout.
func PrintFilterableFields(eventNames []string, jsonOutput bool) error {
	return PrintFilterableFieldsTo(os.Stdout, eventNames, jsonOutput)
}

// PrintFilterableFieldsTo is PrintFilterableFields with an explicit writer (for testing).
func PrintFilterableFieldsTo(w io.Writer, eventNames []string, jsonOutput bool) error {
	reports := make([]EventFilterability, 0, len(eventNames))
	for _, name := range eventNames {
		id, ok := events.Core.GetDefinitionIDByName(name)
		if !ok {
			return fmt.Errorf("unknown event: %q", name)
		}
		def := events.Core.GetDefinitionByID(id)

		rep := EventFilterability{
			Event:       def.GetName(),
			KernelScope: kernelScopeDims,
			ReturnValue: true,
		}
		for _, f := range def.GetFields() {
			if filters.IsKernelFilterableDataField(f.Name) {
				rep.KernelData = append(rep.KernelData, f.Name)
			} else {
				rep.UserSpaceData = append(rep.UserSpaceData, f.Name)
			}
		}
		reports = append(reports, rep)
	}

	if jsonOutput {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(reports)
	}
	return printFilterableTable(w, reports)
}

func printFilterableTable(w io.Writer, reports []EventFilterability) error {
	fmt.Fprintln(w, "Where each filter is enforced: KERNEL filters drop non-matching instances before an")
	fmt.Fprintln(w, "event is submitted; USER-SPACE filters run after submission (the event is collected,")
	fmt.Fprintln(w, "then filtered).")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Workload scope filters (kernel, available on traced events):")
	fmt.Fprintf(w, "  %s\n", strings.Join(kernelScopeDims, ", "))
	fmt.Fprintln(w, "  (tree/follow apply to an event's first 64 rules only)")
	fmt.Fprintln(w)

	for _, r := range reports {
		kd := "(none)"
		if len(r.KernelData) > 0 {
			kd = strings.Join(r.KernelData, ", ")
		}
		userSpace := append([]string(nil), r.UserSpaceData...)
		userSpace = append(userSpace, "retval")

		fmt.Fprintf(w, "Event: %s\n", r.Event)
		fmt.Fprintf(w, "  kernel data filter:  %s\n", kd)
		fmt.Fprintf(w, "  user-space only:     %s\n", strings.Join(userSpace, ", "))
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - Filtering an event in multiple policies/detectors composes as a UNION in the kernel:")
	fmt.Fprintln(w, "    a single broad (unfiltered) selector forces submission for every selector of that event.")
	fmt.Fprintln(w, "  - An event selected by more than 64 rules is always submitted (overflow); user space narrows.")
	return nil
}

// PolicyEventVerdict is the policy-aware filterability verdict for one event.
type PolicyEventVerdict struct {
	Event        string   `json:"event"`
	RuleCount    int      `json:"rule_count"`
	Status       string   `json:"status"` // "kernel", "user-space", or "overflow"
	KernelFilter []string `json:"kernel_filters,omitempty"`
	SubmittedBy  []string `json:"submitted_by,omitempty"` // "policy (reason)" for selectors with no kernel filter
	Hint         string   `json:"hint,omitempty"`
}

// kernelCapableScopeDims are scope dimensions the kernel CAN filter - so a per-rule (user-space) filter
// on one of them can be moved into the policy scope for in-kernel filtering.
var kernelCapableScopeDims = map[string]bool{
	"comm": true, "uid": true, "pid": true, "mntns": true, "pidns": true,
	"uts": true, "container": true, "tree": true, "executable": true,
}

// LoadScenarioConfig reads a Tracee config file and returns the settings that affect the events-pipeline
// filterability report, plus the detector search directories the config configures.
//
// Only two config settings change the report: the DNS cache (it force-collects the non-internal
// net_packet_dns event) and the configured detectors (their base scopes are folded in). The process
// store and capture settings force-collect only INTERNAL, control-plane events (a separate perf buffer),
// and sched_process_exec/fork/exit are always collected regardless, so those settings are intentionally
// not wired here. Policies are NOT read from the config file (they are passed separately).
func LoadScenarioConfig(configPath string) (policy.ManagerConfig, []string, error) {
	viper.SetConfigFile(configPath)
	if err := viper.ReadInConfig(); err != nil {
		return policy.ManagerConfig{}, nil, fmt.Errorf("reading config %q: %w", configPath, err)
	}

	mc := policy.ManagerConfig{}
	if viper.IsSet(flags.StoresFlag) {
		sf, err := flags.GetFlagsFromViper(flags.StoresFlag)
		if err != nil {
			return mc, nil, fmt.Errorf("stores config: %w", err)
		}
		stores, err := flags.PrepareStores(sf)
		if err != nil {
			return mc, nil, fmt.Errorf("stores config: %w", err)
		}
		mc.DNSStoreConfig = stores.GetDNSStoreConfig()
	}

	var detectorDirs []string
	if viper.IsSet(flags.DetectorsFlag) {
		df, err := flags.GetFlagsFromViper(flags.DetectorsFlag)
		if err != nil {
			return mc, nil, fmt.Errorf("detectors config: %w", err)
		}
		dc, err := flags.PrepareDetectors(df)
		if err != nil {
			return mc, nil, fmt.Errorf("detectors config: %w", err)
		}
		detectorDirs = dc.Paths
	}
	return mc, detectorDirs, nil
}

// PrintPolicyFilterability loads policies, computes the REAL rule set (with dependency expansion via the
// policy manager, no eBPF), and prints per event where filtering happens: in the kernel (dropped before
// submission), in user space (submitted, then filtered), or lost to overflow (>64 rules). managerCfg
// mirrors the runtime settings that force-collect events (process store, captures, ...); when
// detectorList is non-empty, the detectors' declared per-base-event scope/data filters (Phase 2) are
// folded onto the base events' dependency rules. Output goes to stdout.
func PrintPolicyFilterability(policyPaths []string, managerCfg policy.ManagerConfig, detectorList []detection.EventDetector, jsonOutput bool) error {
	return PrintPolicyFilterabilityTo(os.Stdout, policyPaths, managerCfg, detectorList, jsonOutput)
}

// PrintPolicyFilterabilityTo is PrintPolicyFilterability with an explicit writer (for testing).
func PrintPolicyFilterabilityTo(w io.Writer, policyPaths []string, managerCfg policy.ManagerConfig, detectorList []detection.EventDetector, jsonOutput bool) error {
	polFiles, err := policyv1beta1.PoliciesFromPaths(policyPaths)
	if err != nil {
		return fmt.Errorf("loading policies: %w", err)
	}
	scopeMap, eventMap, err := flags.PrepareFilterMapsFromPolicies(polFiles, nil)
	if err != nil {
		return fmt.Errorf("parsing policies: %w", err)
	}
	policies, err := flags.CreatePolicies(scopeMap, eventMap)
	if err != nil {
		return fmt.Errorf("building policies: %w", err)
	}

	// Compute the real rule set (dependency expansion + bootstrap) without loading eBPF.
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})
	pm, err := policy.NewManager(managerCfg, depsManager, policies...)
	if err != nil {
		return fmt.Errorf("computing rules: %w", err)
	}

	// Fold in the detectors' Phase-2 per-base-event scope/data filters (threaded onto base dependency
	// rules), so base events pulled in by a policy's detector-output selection carry the detector's scope.
	if len(detectorList) > 0 {
		engine := detectors.NewEngine(pm, nil)
		params := detection.DetectorParams{
			Logger:     logger.Current(),
			DataStores: datastores.NewRegistry(),
			Config:     detection.NewEmptyDetectorConfig(),
		}
		for _, d := range detectorList {
			// A detector whose datastore/enrichment requirements are unavailable here is skipped; its
			// declared filters simply are not folded in (best-effort for a diagnostics command).
			_ = engine.RegisterDetector(d, params)
		}
		pm.SetDetectorScopeFilters(engine.GetDetectorBaseScopeFilters())
		pm.SetDetectorDataFilters(engine.GetDetectorBaseDataFilters())
		if err := pm.RecomputeRules(); err != nil {
			return fmt.Errorf("recomputing rules with detectors: %w", err)
		}
	}

	verdicts := make([]PolicyEventVerdict, 0)
	for _, efi := range pm.GetFilterabilityByEvent() {
		// Skip events pulled in only by the internal bootstrap policy (not touched by the user's policies).
		userTouched := false
		for _, r := range efi.Rules {
			if !r.Bootstrap {
				userTouched = true
				break
			}
		}
		if userTouched {
			verdicts = append(verdicts, buildPolicyVerdict(efi))
		}
	}
	sort.Slice(verdicts, func(i, j int) bool { return verdicts[i].Event < verdicts[j].Event })

	if jsonOutput {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(verdicts)
	}

	policyNoun := "policies"
	if len(policies) == 1 {
		policyNoun = "policy"
	}
	fmt.Fprintf(w, "Analyzed %d %s (with dependency expansion). Where each event is filtered:\n\n", len(policies), policyNoun)
	for _, v := range verdicts {
		fmt.Fprintf(w, "[%s] %s\n", v.Status, v.Event)
		if len(v.KernelFilter) > 0 {
			// On a kernel verdict these filters actually reduce submission; on a user-space/overflow
			// verdict they are kernel-capable but their narrowing is defeated (see "submitted ..." below).
			if v.Status == "kernel" {
				fmt.Fprintf(w, "    kernel narrows by: %s\n", strings.Join(v.KernelFilter, ", "))
			} else {
				fmt.Fprintf(w, "    kernel filters defeated here: %s\n", strings.Join(v.KernelFilter, ", "))
			}
		}
		if len(v.SubmittedBy) > 0 {
			fmt.Fprintf(w, "    submitted to user space by: %s\n", strings.Join(v.SubmittedBy, "; "))
		}
		if v.Hint != "" {
			fmt.Fprintf(w, "    hint: %s\n", v.Hint)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "kernel      = the kernel drops non-matching instances before submission (cheapest).")
	fmt.Fprintln(w, "user-space  = the kernel submits every instance; filtering happens in user space.")
	fmt.Fprintln(w, "overflow    = more than 64 rules select the event, so the kernel submits every instance.")
	fmt.Fprintln(w, "Scope filters (comm/uid/pid/mntns/pidns/container/executable) and pathname data filters")
	fmt.Fprintln(w, "run in the kernel, whether written in spec.scope or a rule's `filters:`; other data fields")
	fmt.Fprintln(w, "and return-value filters run in user space.")
	return nil
}

// buildPolicyVerdict rolls up an event's per-rule filter info into a single verdict.
func buildPolicyVerdict(efi policy.EventFilterInfo) PolicyEventVerdict {
	v := PolicyEventVerdict{Event: efi.EventName, RuleCount: len(efi.Rules)}

	kernelSet := map[string]bool{}
	submitted := map[string]bool{}
	hintDims := map[string]bool{}
	allKernel := true

	for _, r := range efi.Rules {
		if r.KernelNarrows() {
			for _, k := range r.KernelScope {
				kernelSet[k] = true
			}
			for _, k := range r.KernelData {
				kernelSet["data."+k] = true
			}
			continue
		}
		allKernel = false

		if r.Bootstrap {
			submitted["Tracee always collects this (bootstrap)"] = true
			continue
		}
		reason, scopeDims := ruleUserReason(r)
		submitted[fmt.Sprintf("%s (%s)", r.Policy, reason)] = true
		for _, d := range scopeDims {
			if kernelCapableScopeDims[d] {
				hintDims[d] = true
			}
		}
	}

	for k := range kernelSet {
		v.KernelFilter = append(v.KernelFilter, k)
	}
	for s := range submitted {
		v.SubmittedBy = append(v.SubmittedBy, s)
	}
	sort.Strings(v.KernelFilter)
	sort.Strings(v.SubmittedBy)

	switch {
	case v.RuleCount > 64:
		v.Status = "overflow"
	case allKernel:
		v.Status = "kernel"
	default:
		v.Status = "user-space"
	}

	if len(hintDims) > 0 {
		hd := make([]string, 0, len(hintDims))
		for d := range hintDims {
			hd = append(hd, d)
		}
		sort.Strings(hd)
		v.Hint = "move " + strings.Join(hd, "/") + " from the rule `filters:` into the policy `spec.scope:` to filter in the kernel"
	}
	return v
}

// ruleUserReason describes why a rule with no kernel filter still reaches user space, and returns any
// per-rule scope dims involved (for the move-to-policy-scope hint).
func ruleUserReason(r policy.RuleFilterInfo) (string, []string) {
	switch {
	case len(r.UserScope) > 0:
		// A single generic "scope" means the dimension is not one we can name (and cannot advise moving).
		if len(r.UserScope) == 1 && r.UserScope[0] == "scope" {
			return "user-space scope filter", nil
		}
		return "user-space scope: " + strings.Join(r.UserScope, ","), r.UserScope
	case len(r.UserData) > 0:
		return "user-space " + strings.Join(r.UserData, ","), nil
	default:
		return "no filter", nil
	}
}
