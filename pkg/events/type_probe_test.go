package events

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

// NOTE: Probe type describes a single probe, concurrency tests under dep_probes_test.go

// TestProbe_NewProbe tests that NewProbe returns a new probe with the correct handle and flag.
func TestProbe_NewProbe(t *testing.T) {
	probe := NewProbe(12345, true)
	assert.Equal(t, probes.Handle(12345), probe.GetHandle())
	assert.True(t, probe.IsRequired())
}

// TestProbe_SetRequired tests that SetRequired sets the required flag to true.
func TestProbe_SetRequired(t *testing.T) {
	probe := NewProbe(12345, false)
	probe.SetRequired()
	assert.True(t, probe.IsRequired())
}

// TestProbe_SetNotRequired tests that SetNotRequired sets the required flag to false.
func TestProbe_SetNotRequired(t *testing.T) {
	probe := NewProbe(12345, true)
	probe.SetNotRequired()
	assert.False(t, probe.IsRequired())
}
