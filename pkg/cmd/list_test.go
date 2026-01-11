package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/types/trace"
)

// Mock policy for testing
type mockPolicy struct {
	name           string
	description    string
	scope          []string
	defaultActions []string
	rules          []k8s.Rule
}

func (m *mockPolicy) GetName() string             { return m.name }
func (m *mockPolicy) GetDescription() string      { return m.description }
func (m *mockPolicy) GetScope() []string          { return m.scope }
func (m *mockPolicy) GetDefaultActions() []string { return m.defaultActions }
func (m *mockPolicy) GetRules() []k8s.Rule        { return m.rules }

func TestGetEventType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		eventID  events.ID
		expected string
	}{
		{
			name:     "syscall event",
			eventID:  events.Read,
			expected: "syscall",
		},
		{
			name:     "network event",
			eventID:  events.NetPacketIPv4,
			expected: "network",
		},
		{
			name:     "other event",
			eventID:  events.SchedProcessExec,
			expected: "other",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			def := events.Core.GetDefinitionByID(tc.eventID)
			result := getEventType(def)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFieldsToStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fields   []events.DataField
		expected []string
	}{
		{
			name:     "empty fields",
			fields:   []events.DataField{},
			expected: []string{},
		},
		{
			name: "single field",
			fields: []events.DataField{
				{ArgMeta: trace.ArgMeta{Name: "fd", Type: "int"}},
			},
			expected: []string{"int fd"},
		},
		{
			name: "multiple fields",
			fields: []events.DataField{
				{ArgMeta: trace.ArgMeta{Name: "fd", Type: "int"}},
				{ArgMeta: trace.ArgMeta{Name: "buf", Type: "void*"}},
				{ArgMeta: trace.ArgMeta{Name: "count", Type: "size_t"}},
			},
			expected: []string{"int fd", "void* buf", "size_t count"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := fieldsToStrings(tc.fields)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestEventInfo(t *testing.T) {
	t.Parallel()

	info := EventInfo{
		Name:        "test_event",
		ID:          123,
		Version:     "1.0.0",
		Description: "A test event",
		Tags:        []string{"test", "example"},
		Type:        "syscall",
		Arguments:   []string{"int fd", "void* buf"},
	}

	assert.Equal(t, "test_event", info.Name)
	assert.Equal(t, 123, info.ID)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "A test event", info.Description)
	assert.Equal(t, []string{"test", "example"}, info.Tags)
	assert.Equal(t, "syscall", info.Type)
	assert.Equal(t, []string{"int fd", "void* buf"}, info.Arguments)
}

func TestDetectorInfo(t *testing.T) {
	t.Parallel()

	info := DetectorInfo{
		ID:             "DET-001",
		Name:           "test_detector",
		Description:    "A test detector",
		Severity:       "high",
		RequiredEvents: []string{"execve", "open"},
		MITRETactic:    "execution",
		MITRETechnique: "T1059",
	}

	assert.Equal(t, "DET-001", info.ID)
	assert.Equal(t, "test_detector", info.Name)
	assert.Equal(t, "A test detector", info.Description)
	assert.Equal(t, "high", info.Severity)
	assert.Equal(t, []string{"execve", "open"}, info.RequiredEvents)
	assert.Equal(t, "execution", info.MITRETactic)
	assert.Equal(t, "T1059", info.MITRETechnique)
}

func TestPolicyInfo(t *testing.T) {
	t.Parallel()

	info := PolicyInfo{
		Name:        "test_policy",
		Description: "A test policy",
		Scope:       []string{"container", "host"},
		RuleCount:   5,
	}

	assert.Equal(t, "test_policy", info.Name)
	assert.Equal(t, "A test policy", info.Description)
	assert.Equal(t, []string{"container", "host"}, info.Scope)
	assert.Equal(t, 5, info.RuleCount)
}

// Event list tests

func TestPrintEventListToSingleEvent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Names: []string{"read"},
	}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "matching filters")
	assert.Contains(t, output, "read")
}

func TestPrintEventListToJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Names: []string{"read"},
	}, true)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, `"name"`)
	assert.Contains(t, output, `"read"`)

	// Verify it's valid JSON
	var eventInfos []EventInfo
	err = json.Unmarshal(buf.Bytes(), &eventInfos)
	require.NoError(t, err)
	assert.Len(t, eventInfos, 1)
	assert.Equal(t, "read", eventInfos[0].Name)
}

func TestPrintEventListToNoMatches(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Names: []string{"nonexistent_event_xyz"},
	}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No events match")
}

func TestPrintEventListToMultipleEvents(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	// Use comma-separated values for OR logic (matches read OR write)
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Names: []string{"read,write"},
	}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "matching filters")
	assert.Contains(t, output, "read")
	assert.Contains(t, output, "write")
}

func TestPrintEventListToByType(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Types: []string{"network"},
	}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "matching filters")
	assert.Contains(t, output, "Network Events")
}

// Detector list tests

func TestPrintDetectorListToEmpty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintDetectorListTo(&buf, nil, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No detectors found")
}

func TestPrintDetectorListToEmptyJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintDetectorListTo(&buf, nil, true)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[]")

	// Verify it's valid JSON
	var detectors []DetectorInfo
	err = json.Unmarshal(buf.Bytes(), &detectors)
	require.NoError(t, err)
	assert.Empty(t, detectors)
}

// Policy list tests

func TestPrintPolicyListToEmpty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintPolicyListTo(&buf, nil, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No policies found")
}

func TestPrintPolicyListToEmptyJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintPolicyListTo(&buf, nil, true)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[]")

	// Verify it's valid JSON
	var policies []PolicyInfo
	err = json.Unmarshal(buf.Bytes(), &policies)
	require.NoError(t, err)
	assert.Empty(t, policies)
}

// Test multiple syscall events
func TestPrintEventListToSyscallType(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Types: []string{"syscall"},
		Names: []string{"read"},
	}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Syscall Events")
}

// Test JSON output for multiple events
func TestPrintEventListToJSONMultiple(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Names: []string{"read,write,open"},
	}, true)
	require.NoError(t, err)

	// Verify it's valid JSON array
	var eventInfos []EventInfo
	err = json.Unmarshal(buf.Bytes(), &eventInfos)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(eventInfos), 2)
}

// Test tag filter
func TestPrintEventListToByTag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Tags:  []string{"fs"},
		Names: []string{"read"},
	}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "matching filters")
}

// Test combined filters
func TestPrintEventListToCombinedFilters(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Types: []string{"syscall"},
		Tags:  []string{"fs"},
		Names: []string{"*"},
	}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "matching filters")
}

// Test "other" event type category
func TestPrintEventListToOtherType(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	// sched_process_exec is an "other" type event
	err := PrintEventListTo(&buf, flags.EventListFilters{
		Names: []string{"sched_process_exec"},
	}, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Other Events")
}

// Policy tests with mock data

func TestPrintPolicyListToWithData(t *testing.T) {
	t.Parallel()

	policies := []k8s.PolicyInterface{
		&mockPolicy{
			name:        "test-policy",
			description: "A test policy for unit testing",
			scope:       []string{"container", "host"},
			rules:       []k8s.Rule{{}, {}, {}}, // 3 rules
		},
	}

	var buf bytes.Buffer
	err := PrintPolicyListTo(&buf, policies, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Available policies (1)")
	assert.Contains(t, output, "test-policy")
	assert.Contains(t, output, "A test policy")
	assert.Contains(t, output, "container")
	assert.Contains(t, output, "3")
}

func TestPrintPolicyListToWithDataJSON(t *testing.T) {
	t.Parallel()

	policies := []k8s.PolicyInterface{
		&mockPolicy{
			name:        "json-test-policy",
			description: "A test policy for JSON output",
			scope:       []string{"container"},
			rules:       []k8s.Rule{{}, {}}, // 2 rules
		},
	}

	var buf bytes.Buffer
	err := PrintPolicyListTo(&buf, policies, true)
	require.NoError(t, err)

	var infos []PolicyInfo
	err = json.Unmarshal(buf.Bytes(), &infos)
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, "json-test-policy", infos[0].Name)
	assert.Equal(t, "A test policy for JSON output", infos[0].Description)
	assert.Equal(t, []string{"container"}, infos[0].Scope)
	assert.Equal(t, 2, infos[0].RuleCount)
}

func TestPrintPolicyListToLongScope(t *testing.T) {
	t.Parallel()

	// Test truncation of long scope
	policies := []k8s.PolicyInterface{
		&mockPolicy{
			name:        "long-scope-policy",
			description: "A policy with a very long scope list",
			scope:       []string{"scope1", "scope2", "scope3", "scope4", "scope5", "scope6", "scope7", "scope8"},
			rules:       []k8s.Rule{{}},
		},
	}

	var buf bytes.Buffer
	err := PrintPolicyListTo(&buf, policies, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "long-scope-policy")
	// Long scopes should be truncated with "..."
	assert.Contains(t, output, "...")
}
