package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/datastores/process"
	"github.com/aquasecurity/tracee/pkg/detectors"
	yamldetectors "github.com/aquasecurity/tracee/pkg/detectors/yaml"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func TestPrintFilterableFieldsTo_Static(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, PrintFilterableFieldsTo(&buf, []string{"security_file_open"}, false))
	out := buf.String()

	require.Contains(t, out, "Event: security_file_open")
	// pathname is the one kernel-capable data field.
	require.Contains(t, out, "kernel data filter:  pathname")
	// a non-pathname field is user-space only.
	require.Contains(t, out, "flags")
	require.Contains(t, out, "user-space only:")
	// scope dims are advertised as kernel filters.
	require.Contains(t, out, "comm, uid, pid")
}

func TestPrintFilterableFieldsTo_JSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, PrintFilterableFieldsTo(&buf, []string{"security_file_open"}, true))
	out := buf.String()
	require.Contains(t, out, `"event": "security_file_open"`)
	require.Contains(t, out, `"kernel_data"`)
	require.Contains(t, out, `"pathname"`)
}

func TestPrintFilterableFieldsTo_UnknownEvent(t *testing.T) {
	var buf bytes.Buffer
	err := PrintFilterableFieldsTo(&buf, []string{"no_such_event_xyz"}, false)
	require.Error(t, err)
}

func TestPrintEventDepsTo_Formats(t *testing.T) {
	// tree
	var tree bytes.Buffer
	require.NoError(t, PrintEventDepsTo(&tree, []string{"net_packet_icmp"}, "tree"))
	require.Contains(t, tree.String(), "net_packet_icmp")
	require.Contains(t, tree.String(), "net_packet_icmp_base")

	// mermaid
	var mm bytes.Buffer
	require.NoError(t, PrintEventDepsTo(&mm, []string{"net_packet_icmp"}, "mermaid"))
	require.Contains(t, mm.String(), "flowchart TD")
	require.Contains(t, mm.String(), "net_packet_icmp --> net_packet_icmp_base")

	// json
	var js bytes.Buffer
	require.NoError(t, PrintEventDepsTo(&js, []string{"net_packet_icmp"}, "json"))
	require.Contains(t, js.String(), `"depends_on"`)

	// unknown format / event
	require.Error(t, PrintEventDepsTo(&bytes.Buffer{}, []string{"net_packet_icmp"}, "bogus"))
	require.Error(t, PrintEventDepsTo(&bytes.Buffer{}, []string{"no_such_event_xyz"}, "tree"))
}

func TestPrintPolicyFilterabilityTo_DefeatAndNarrow(t *testing.T) {
	dir := t.TempDir()
	broad := `apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: broad-exec
spec:
  scope:
    - global
  rules:
    - event: sched_process_exec
`
	scoped := `apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: scoped-open
spec:
  scope:
    - comm=bash
  rules:
    - event: security_file_open
      filters:
        - data.pathname=/etc/*
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "broad.yaml"), []byte(broad), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scoped.yaml"), []byte(scoped), 0o644))

	var buf bytes.Buffer
	require.NoError(t, PrintPolicyFilterabilityTo(&buf, []string{dir}, policy.ManagerConfig{}, nil, false))
	out := buf.String()

	// The unfiltered selection of sched_process_exec keeps it in user space (and broad-exec is named).
	require.Regexp(t, `\[user-space\] sched_process_exec`, out)
	require.Contains(t, out, "broad-exec")
	// security_file_open is narrowed in the kernel by comm + pathname.
	require.Regexp(t, `\[kernel\] security_file_open`, out)
	require.True(t, strings.Contains(out, "comm") && strings.Contains(out, "data.pathname"))
}

// policyFilterabilityOutput writes the given policy files into a temp dir and returns the text output of
// PrintPolicyFilterabilityTo for them.
func policyFilterabilityOutput(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	var buf bytes.Buffer
	require.NoError(t, PrintPolicyFilterabilityTo(&buf, []string{dir}, policy.ManagerConfig{}, nil, false))
	return buf.String()
}

func policyYAML(name, scope, event string, ruleFilters ...string) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "apiVersion: tracee.aquasec.com/v1beta1\nkind: Policy\nmetadata:\n  name: %s\nspec:\n  scope:\n    - %s\n  rules:\n    - event: %s\n", name, scope, event)
	if len(ruleFilters) > 0 {
		fmt.Fprintf(b, "      filters:\n")
		for _, f := range ruleFilters {
			fmt.Fprintf(b, "        - %s\n", f)
		}
	}
	return b.String()
}

// TestPolicyFilterability_Scenarios covers the four-way classification (kernel/user-space, scope/data).
func TestPolicyFilterability_Scenarios(t *testing.T) {
	// Policy spec.scope -> kernel (openat is not bootstrap-forced).
	out := policyFilterabilityOutput(t, map[string]string{"p.yaml": policyYAML("p", "comm=nginx", "openat")})
	require.Regexp(t, `\[kernel\] openat`, out)
	require.Contains(t, out, "kernel narrows by: comm")

	// Per-rule scope on a kernel-pushable dim (comm) is pushed to the kernel too (not just spec.scope).
	out = policyFilterabilityOutput(t, map[string]string{"p.yaml": policyYAML("p", "global", "openat", "comm=nginx")})
	require.Regexp(t, `\[kernel\] openat`, out)
	require.Contains(t, out, "comm (rule)")

	// pathname data filter -> kernel.
	out = policyFilterabilityOutput(t, map[string]string{"p.yaml": policyYAML("p", "global", "security_file_open", "data.pathname=/etc/*")})
	require.Regexp(t, `\[kernel\] security_file_open`, out)
	require.Contains(t, out, "data.pathname")

	// retval filter -> user space.
	out = policyFilterabilityOutput(t, map[string]string{"p.yaml": policyYAML("p", "global", "close", "retval!=0")})
	require.Regexp(t, `\[user-space\] close`, out)
	require.Contains(t, out, "user-space retval")
}

// TestPolicyFilterability_BootstrapDefeat: scoping an always-collected event does not help in the kernel.
func TestPolicyFilterability_BootstrapDefeat(t *testing.T) {
	out := policyFilterabilityOutput(t, map[string]string{"p.yaml": policyYAML("p", "comm=bash", "sched_process_exec")})
	require.Regexp(t, `\[user-space\] sched_process_exec`, out)
	require.Contains(t, out, "bootstrap")
}

// TestPolicyFilterability_UnionDefeat: a broad co-selector forces submission despite a scoped one.
func TestPolicyFilterability_UnionDefeat(t *testing.T) {
	out := policyFilterabilityOutput(t, map[string]string{
		"scoped.yaml": policyYAML("scoped", "comm=nginx", "openat"),
		"broad.yaml":  policyYAML("broad", "global", "openat"),
	})
	require.Regexp(t, `\[user-space\] openat`, out)
	require.Contains(t, out, "kernel narrows by: comm")
	require.Contains(t, out, "broad (no filter)")
}

// TestPolicyFilterability_Overflow: more than 64 rules on one event -> always submitted (overflow).
func TestPolicyFilterability_Overflow(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 65; i++ {
		files[fmt.Sprintf("p%02d.yaml", i)] = policyYAML(fmt.Sprintf("pol-%02d", i), fmt.Sprintf("comm=c%02d", i), "openat")
	}
	out := policyFilterabilityOutput(t, files)
	require.Regexp(t, `\[overflow\] openat`, out)
}

// TestPolicyFilterability_JSON checks the machine-readable output shape.
func TestPolicyFilterability_JSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(policyYAML("p", "comm=nginx", "openat")), 0o644))
	var buf bytes.Buffer
	require.NoError(t, PrintPolicyFilterabilityTo(&buf, []string{dir}, policy.ManagerConfig{}, nil, true))

	var verdicts []map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &verdicts))
	found := false
	for _, v := range verdicts {
		if v["event"] == "openat" {
			found = true
			require.Equal(t, "kernel", v["status"])
		}
	}
	require.True(t, found, "openat verdict must be present in JSON")
}

// TestPolicyFilterability_Examples verifies the shipped example policies still produce their documented
// verdicts (keeps examples/policies/yaml/filterability in sync with the tool).
func TestPolicyFilterability_Examples(t *testing.T) {
	base := "../../examples/policies/yaml/filterability"
	cases := map[string]string{
		"kernel-scope.yaml":               `\[kernel\] openat`,
		"kernel-rule-scope.yaml":          `\[kernel\] openat`,
		"kernel-pathname.yaml":            `\[kernel\] security_file_open`,
		"userspace-retval.yaml":           `\[user-space\] close`,
		"bootstrap-always-collected.yaml": `\[user-space\] sched_process_exec`,
	}
	for file, want := range cases {
		var buf bytes.Buffer
		require.NoError(t, PrintPolicyFilterabilityTo(&buf, []string{filepath.Join(base, file)}, policy.ManagerConfig{}, nil, false), file)
		require.Regexp(t, want, buf.String(), file)
	}
	var buf bytes.Buffer
	require.NoError(t, PrintPolicyFilterabilityTo(&buf, []string{filepath.Join(base, "union-defeat")}, policy.ManagerConfig{}, nil, false))
	require.Regexp(t, `\[user-space\] openat`, buf.String())
}

// TestPolicyFilterability_Detectors verifies --detectors folds a detector's declared base scope filter
// onto the base event (flipping it from user-space to kernel).
func TestPolicyFilterability_Detectors(t *testing.T) {
	detDir := t.TempDir()
	detYAML := `type: detector
id: filt-example-det
produced_event:
  name: test_filt_example
  version: 1.0.0
  description: filterability detector test
  tags:
    - test
  fields:
    - name: p
      type: string
requirements:
  min_tracee_version: 0.0.0
  events:
    - name: security_file_open
      dependency: required
      scope_filters:
        - comm=detcomm
auto_populate:
  detected_from: true
output:
  fields:
    - name: p
      expression: getEventData("pathname")
`
	require.NoError(t, os.WriteFile(filepath.Join(detDir, "d.yaml"), []byte(detYAML), 0o644))
	loaded := yamldetectors.LoadFromDirectories([]string{detDir})
	require.NotEmpty(t, loaded.Detectors)
	_, err := detectors.CreateEventsFromDetectors(events.StartDetectorID, loaded.Detectors)
	require.NoError(t, err)

	polDir := t.TempDir()
	pol := `apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: uses-det
spec:
  scope:
    - global
  rules:
    - event: test_filt_example
`
	require.NoError(t, os.WriteFile(filepath.Join(polDir, "p.yaml"), []byte(pol), 0o644))

	// Without folding, the base event is pulled in with no kernel scope.
	var without bytes.Buffer
	require.NoError(t, PrintPolicyFilterabilityTo(&without, []string{polDir}, policy.ManagerConfig{}, nil, false))
	require.Regexp(t, `\[user-space\] security_file_open`, without.String())

	// With the detector's declared base scope folded in, it becomes kernel-narrowed.
	var with bytes.Buffer
	require.NoError(t, PrintPolicyFilterabilityTo(&with, []string{polDir}, policy.ManagerConfig{}, loaded.Detectors, false))
	require.Regexp(t, `\[kernel\] security_file_open`, with.String())
	require.Contains(t, with.String(), "comm (detector)")

	// The detector OUTPUT event itself is excluded (produced in user space).
	require.NotContains(t, with.String(), "test_filt_example")
}

// TestLoadScenarioConfig checks that a Tracee config file maps to the ManagerConfig settings that affect
// the report - the DNS cache (which force-collects the non-internal net_packet_dns event). The process
// store is intentionally NOT wired (it force-collects only internal control-plane events).
func TestLoadScenarioConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "tracee.yaml")
	cfg := `stores:
  dns:
    enabled: true
  process:
    enabled: true
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o644))

	mc, detectorDirs, err := LoadScenarioConfig(cfgPath)
	require.NoError(t, err)
	require.True(t, mc.DNSStoreConfig.Enable, "DNS cache should be reflected (net_packet_dns force-collect)")
	// process store is inert for the report and intentionally not wired.
	require.Equal(t, process.SourceNone, mc.ProcessStoreConfig.Source)
	require.Empty(t, detectorDirs)
}
