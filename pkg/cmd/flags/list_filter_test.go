package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

func TestParseEventFilters_ListCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		expected EventListFilters
	}{
		{
			name:     "empty args",
			args:     []string{},
			expected: EventListFilters{},
		},
		{
			name: "event name",
			args: []string{"open"},
			expected: EventListFilters{
				Names: []string{"open"},
			},
		},
		{
			name: "wildcard pattern",
			args: []string{"open*"},
			expected: EventListFilters{
				Names: []string{"open*"},
			},
		},
		{
			name: "tag filter",
			args: []string{"tag=fs"},
			expected: EventListFilters{
				Tags: []string{"fs"},
			},
		},
		{
			name: "set filter (alias for tag)",
			args: []string{"set=network"},
			expected: EventListFilters{
				Tags: []string{"network"},
			},
		},
		{
			name: "type filter",
			args: []string{"type=syscall"},
			expected: EventListFilters{
				Types: []string{"syscall"},
			},
		},
		{
			name: "severity filter",
			args: []string{"threat.severity=critical"},
			expected: EventListFilters{
				Severities: []string{"critical"},
			},
		},
		{
			name: "technique filter",
			args: []string{"threat.mitre.technique=T1055"},
			expected: EventListFilters{
				Techniques: []string{"T1055"},
			},
		},
		{
			name: "tactic filter",
			args: []string{"threat.mitre.tactic=Execution"},
			expected: EventListFilters{
				Tactics: []string{"Execution"},
			},
		},
		{
			name: "multiple filters",
			args: []string{"tag=fs", "threat.severity=high", "open*"},
			expected: EventListFilters{
				Tags:       []string{"fs"},
				Severities: []string{"high"},
				Names:      []string{"open*"},
			},
		},
		{
			name: "comma-separated values in tag",
			args: []string{"tag=fs,network"},
			expected: EventListFilters{
				Tags: []string{"fs,network"},
			},
		},
		{
			name: "unknown key=value treated as name",
			args: []string{"unknown=value"},
			expected: EventListFilters{
				Names: []string{"unknown=value"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseEventFilters(tt.args)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestEventListFilters_HasFilters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filters  EventListFilters
		expected bool
	}{
		{
			name:     "empty filters",
			filters:  EventListFilters{},
			expected: false,
		},
		{
			name:     "tag filter only",
			filters:  EventListFilters{Tags: []string{"fs"}},
			expected: true,
		},
		{
			name:     "type filter only",
			filters:  EventListFilters{Types: []string{"syscall"}},
			expected: true,
		},
		{
			name:     "severity filter only",
			filters:  EventListFilters{Severities: []string{"critical"}},
			expected: true,
		},
		{
			name:     "name filter only",
			filters:  EventListFilters{Names: []string{"open*"}},
			expected: true,
		},
		{
			name: "multiple filters",
			filters: EventListFilters{
				Tags:  []string{"fs"},
				Types: []string{"syscall"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filters.HasFilters()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTrim(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single value",
			input:    "fs",
			expected: []string{"fs"},
		},
		{
			name:     "comma separated",
			input:    "fs,network",
			expected: []string{"fs", "network"},
		},
		{
			name:     "with whitespace",
			input:    "fs , network , proc",
			expected: []string{"fs", "network", "proc"},
		},
		{
			name:     "empty parts ignored",
			input:    "fs,,network",
			expected: []string{"fs", "network"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		pattern  string
		expected bool
	}{
		{
			name:     "exact match",
			input:    "openat",
			pattern:  "openat",
			expected: true,
		},
		{
			name:     "exact match case insensitive",
			input:    "OpenAt",
			pattern:  "openat",
			expected: true,
		},
		{
			name:     "prefix wildcard",
			input:    "openat",
			pattern:  "open*",
			expected: true,
		},
		{
			name:     "prefix wildcard no match",
			input:    "closeat",
			pattern:  "open*",
			expected: false,
		},
		{
			name:     "suffix wildcard",
			input:    "openat",
			pattern:  "*at",
			expected: true,
		},
		{
			name:     "suffix wildcard no match",
			input:    "openfd",
			pattern:  "*at",
			expected: false,
		},
		{
			name:     "contains wildcard",
			input:    "security_file_open",
			pattern:  "*file*",
			expected: true,
		},
		{
			name:     "contains wildcard no match",
			input:    "execve",
			pattern:  "*file*",
			expected: false,
		},
		{
			name:     "no match",
			input:    "openat",
			pattern:  "close",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchPattern(tt.input, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchesAnyTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		eventTags  []string
		filterTags []string
		expected   bool
	}{
		{
			name:       "single tag match",
			eventTags:  []string{"syscalls", "fs"},
			filterTags: []string{"fs"},
			expected:   true,
		},
		{
			name:       "no match",
			eventTags:  []string{"syscalls", "fs"},
			filterTags: []string{"network"},
			expected:   false,
		},
		{
			name:       "case insensitive match",
			eventTags:  []string{"syscalls", "FS"},
			filterTags: []string{"fs"},
			expected:   true,
		},
		{
			name:       "multiple filter tags OR",
			eventTags:  []string{"syscalls", "fs"},
			filterTags: []string{"network", "fs"},
			expected:   true,
		},
		{
			name:       "empty event tags",
			eventTags:  []string{},
			filterTags: []string{"fs"},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesAnyTag(tt.eventTags, tt.filterTags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchesAnyType(t *testing.T) {
	t.Parallel()

	// Create test event definitions
	syscallDef := events.NewDefinition(
		events.ID(1), events.ID(1), "test_syscall", events.NewVersion(1, 0, 0),
		"test", false, true, []string{}, events.DependencyStrategy{}, nil, nil,
	)

	networkDef := events.NewDefinition(
		events.ID(events.NetPacketIPv4), events.ID(events.NetPacketIPv4), "net_packet",
		events.NewVersion(1, 0, 0), "test", false, false, []string{}, events.DependencyStrategy{}, nil, nil,
	)

	tests := []struct {
		name     string
		def      events.Definition
		types    []string
		expected bool
	}{
		{
			name:     "syscall type match",
			def:      syscallDef,
			types:    []string{"syscall"},
			expected: true,
		},
		{
			name:     "syscall type no match",
			def:      syscallDef,
			types:    []string{"network"},
			expected: false,
		},
		{
			name:     "network type match",
			def:      networkDef,
			types:    []string{"network"},
			expected: true,
		},
		{
			name:     "multiple types OR",
			def:      syscallDef,
			types:    []string{"network", "syscall"},
			expected: true,
		},
		{
			name:     "case insensitive",
			def:      syscallDef,
			types:    []string{"SYSCALL"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesAnyType(tt.def, tt.types)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEventListFilters_MatchesEvent(t *testing.T) {
	t.Parallel()

	// Create a test syscall event definition
	syscallDef := events.NewDefinition(
		events.ID(1), events.ID(1), "openat", events.NewVersion(1, 0, 0),
		"open file", false, true, []string{"syscalls", "fs", "fs_file_ops"}, events.DependencyStrategy{}, nil, nil,
	)

	tests := []struct {
		name     string
		filters  EventListFilters
		expected bool
	}{
		{
			name:     "no filters matches everything",
			filters:  EventListFilters{},
			expected: true,
		},
		{
			name:     "tag filter match",
			filters:  EventListFilters{Tags: []string{"fs"}},
			expected: true,
		},
		{
			name:     "tag filter no match",
			filters:  EventListFilters{Tags: []string{"network"}},
			expected: false,
		},
		{
			name:     "type filter match",
			filters:  EventListFilters{Types: []string{"syscall"}},
			expected: true,
		},
		{
			name:     "type filter no match",
			filters:  EventListFilters{Types: []string{"detector"}},
			expected: false,
		},
		{
			name:     "name filter match",
			filters:  EventListFilters{Names: []string{"open*"}},
			expected: true,
		},
		{
			name:     "name filter no match",
			filters:  EventListFilters{Names: []string{"close*"}},
			expected: false,
		},
		{
			name: "multiple tag filters AND",
			filters: EventListFilters{
				Tags: []string{"fs", "syscalls"},
			},
			expected: true,
		},
		{
			name: "multiple tag filters AND - one missing",
			filters: EventListFilters{
				Tags: []string{"fs", "network"},
			},
			expected: false,
		},
		{
			name:     "comma separated tags OR",
			filters:  EventListFilters{Tags: []string{"network,fs"}},
			expected: true,
		},
		{
			name: "combined filters AND",
			filters: EventListFilters{
				Tags:  []string{"fs"},
				Types: []string{"syscall"},
				Names: []string{"open*"},
			},
			expected: true,
		},
		{
			name: "combined filters AND - one fails",
			filters: EventListFilters{
				Tags:  []string{"fs"},
				Types: []string{"detector"},
				Names: []string{"open*"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filters.MatchesEvent(syscallDef)
			assert.Equal(t, tt.expected, result)
		})
	}
}
