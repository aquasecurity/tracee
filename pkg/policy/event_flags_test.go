package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/utils"
)

// TestNewEventFlags tests the newEventFlags function.
func TestNewEventFlags(t *testing.T) {
	t.Parallel()

	ef := newEventFlags()
	emit := uint64(0)
	submit := uint64(0)

	assert.Equal(t, emit, ef.rulesToSubmit)
	assert.Equal(t, submit, ef.rulesToEmit)
	assert.False(t, ef.enabled)

	submit = uint64(1 << 0)
	emit = uint64(1<<1 | 1<<2)
	efWithOptions := newEventFlags(
		eventFlagsWithSubmit(submit),
		eventFlagsWithEmit(emit),
		eventFlagsWithEnabled(true),
	)
	assert.Equal(t, submit, efWithOptions.rulesToSubmit)
	assert.Equal(t, emit, efWithOptions.rulesToEmit)
	assert.True(t, efWithOptions.enabled)
}

// TestEnableSubmission tests the enableSubmission function.
func TestEnableSubmission(t *testing.T) {
	t.Parallel()

	ef := newEventFlags()
	ef.enableSubmission(1)
	assert.True(t, utils.HasBit(ef.rulesToSubmit, 1))
}

// TestEnableEmission tests the enableEmission function.
func TestEnableEmission(t *testing.T) {
	t.Parallel()

	ef := newEventFlags()
	ef.enableEmission(1)
	assert.True(t, utils.HasBit(ef.rulesToEmit, 1))

	ef.enableEmission(-1)
}

// TestDisableSubmission tests the disableSubmission function.
func TestDisableSubmission(t *testing.T) {
	t.Parallel()

	ef := newEventFlags()
	ef.enableSubmission(42)
	ef.disableSubmission(42)
	assert.False(t, utils.HasBit(ef.rulesToSubmit, 42))
}

// TestDisableEmission tests the disableEmission function.
func TestDisableEmission(t *testing.T) {
	t.Parallel()

	ef := newEventFlags()
	ef.enableEmission(42)
	ef.disableEmission(42)
	assert.False(t, utils.HasBit(ef.rulesToEmit, 42))
}

// TestEnableEvent tests the enableEvent function.
func TestEnableEvent(t *testing.T) {
	t.Parallel()

	ef := newEventFlags(eventFlagsWithEnabled(false))
	ef.enableEvent()
	assert.True(t, ef.enabled)
}

// TestDisableEvent tests the disableEvent function.
func TestDisableEvent(t *testing.T) {
	t.Parallel()

	ef := newEventFlags(eventFlagsWithEnabled(true))
	ef.disableEvent()
	assert.False(t, ef.enabled)
}
