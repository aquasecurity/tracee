package capabilities

import (
	"errors"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Test_Initialize_And_GetInstance_Concurrent tests Initialize and GetInstance methods concurrently.
func Test_Initialize_And_GetInstance_Concurrent(t *testing.T) {
	defer goleak.VerifyNone(t)

	var wg sync.WaitGroup
	const numGoroutines = 1000
	wg.Add(numGoroutines * 2) // 2 methods to test concurrently

	// Testing GetInstance method
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			caps := GetInstance()
			assert.NotNil(t, caps)
		}()
	}

	// Testing Initialize method
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			err := Initialize(Config{
				Bypass: true,
			})
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
}

// TestCapabilities_Concurrent tests all public methods of Capabilities concurrently.
func TestCapabilities_Concurrent(t *testing.T) {
	defer goleak.VerifyNone(t)

	assureIsRoot(t)

	var wg sync.WaitGroup
	const numGoroutines = 1000
	wg.Add(numGoroutines * 7) // 7 methods to test concurrently

	// Testing GetInstance/Full methods
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			caps := GetInstance()
			err := caps.Full(func() error {
				return nil
			})
			assert.NoError(t, err)
		}()
	}

	// Testing GetInstance/EBPF methods
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			caps := GetInstance()
			err := caps.EBPF(func() error {
				return nil
			})
			assert.NoError(t, err)
		}()
	}

	// Testing GetInstance/Specific methods
	values := []cap.Value{cap.SYS_ADMIN}
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			caps := GetInstance()
			err := caps.Specific(func() error {
				return nil
			}, values...)
			assert.NoError(t, err)
		}()
	}

	// Testing GetInstance/EBPFRingAdd methods
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			caps := GetInstance()
			err := caps.EBPFRingAdd(cap.BPF, cap.PERFMON)
			assert.NoError(t, err)
		}()
	}

	// Testing GetInstance/EBPFRingRemove methods
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			caps := GetInstance()
			err := caps.EBPFRingRemove(cap.BPF, cap.PERFMON)
			assert.NoError(t, err)
		}()
	}

	// Testing GetInstance/BaseRingAdd methods
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			caps := GetInstance()
			err := caps.BaseRingAdd(cap.SYS_PTRACE)
			assert.NoError(t, err)
		}()
	}

	// Testing GetInstance/BaseRingRemove methods
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			caps := GetInstance()
			err := caps.BaseRingRemove(cap.SYS_PTRACE)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
}

// assureIsRoot skips the test if it is not run as root
func assureIsRoot(t *testing.T) {
	if syscall.Geteuid() != 0 {
		t.Skipf("***** %s must be run as ROOT *****", t.Name())
	}
}

func TestInitialize_MultipleCalls(t *testing.T) {
	// First call should succeed
	err1 := Initialize(Config{Bypass: true})
	require.NoError(t, err1)

	// Subsequent calls should also succeed (singleton pattern)
	err2 := Initialize(Config{Bypass: true})
	require.NoError(t, err2)

	// Both should return the same instance
	caps1 := GetInstance()
	caps2 := GetInstance()
	assert.Equal(t, caps1, caps2)
}

func TestCapabilities_Full_WithBypass(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	callbackExecuted := false
	err = caps.Full(func() error {
		callbackExecuted = true
		return nil
	})

	assert.NoError(t, err)
	assert.True(t, callbackExecuted, "Callback should have been executed")
}

func TestCapabilities_Full_CallbackError(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	expectedErr := errors.New("callback error")
	err = caps.Full(func() error {
		return expectedErr
	})

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestCapabilities_EBPF_WithBypass(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	callbackExecuted := false
	err = caps.EBPF(func() error {
		callbackExecuted = true
		return nil
	})

	assert.NoError(t, err)
	assert.True(t, callbackExecuted, "Callback should have been executed")
}

func TestCapabilities_Specific_WithBypass(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	callbackExecuted := false
	err = caps.Specific(func() error {
		callbackExecuted = true
		return nil
	}, cap.SYS_ADMIN)

	assert.NoError(t, err)
	assert.True(t, callbackExecuted, "Callback should have been executed")
}

func TestReqByString_ValidCapabilities(t *testing.T) {
	// Get the actual string format from the library
	actualFormat := cap.SYS_ADMIN.String()
	values, err := ReqByString(actualFormat)
	require.NoError(t, err)
	require.Len(t, values, 1)
	assert.Equal(t, cap.SYS_ADMIN, values[0])
}

func TestReqByString_InvalidCapability(t *testing.T) {
	values, err := ReqByString("CAP_INVALID_CAPABILITY")
	assert.Error(t, err)
	assert.Nil(t, values)
	assert.Contains(t, err.Error(), "could not find capability")
}

func TestReqByString_MultipleCapabilities(t *testing.T) {
	// Get the actual string format from the library
	sysAdminStr := cap.SYS_ADMIN.String()
	netAdminStr := cap.NET_ADMIN.String()
	values, err := ReqByString(sysAdminStr, netAdminStr)
	require.NoError(t, err)
	require.Len(t, values, 2)
	assert.Equal(t, cap.SYS_ADMIN, values[0])
	assert.Equal(t, cap.NET_ADMIN, values[1])
}

func TestReqByString_EmptyList(t *testing.T) {
	values, err := ReqByString()
	require.NoError(t, err)
	assert.Empty(t, values)
}

func TestListAvailCaps(t *testing.T) {
	caps := ListAvailCaps()
	require.NotEmpty(t, caps)

	// Verify it contains expected capabilities by checking against actual format
	expectedCap := cap.SYS_ADMIN.String()
	found := false
	for _, c := range caps {
		if c == expectedCap {
			found = true
			break
		}
	}
	assert.True(t, found, "Should contain %s", expectedCap)
}

func TestCapabilities_EBPFRingAdd_StateUpdate(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	// Clean up any existing state from previous tests
	cleanupCapabilities(caps, cap.SYS_PTRACE)

	// Initially, CAP_SYS_PTRACE should not be in EBPF ring
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should not be in EBPF ring initially")

	// Add to EBPF ring
	err = caps.EBPFRingAdd(cap.SYS_PTRACE)
	require.NoError(t, err)

	// Verify it's now in EBPF ring
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should be in EBPF ring after EBPFRingAdd")

	// Verify it's NOT in Base ring (EBPFRingAdd only adds to EBPF)
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, Base), "CAP_SYS_PTRACE should not be in Base ring after EBPFRingAdd")

	// Verify it's NOT in Specific ring
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, Specific), "CAP_SYS_PTRACE should not be in Specific ring after EBPFRingAdd")
}

func TestCapabilities_BaseRingAdd_PropagatesToAllRings(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	// Clean up any existing state from previous tests (singleton pattern means state persists)
	cleanupCapabilities(caps, cap.SYS_PTRACE)

	// Initially, CAP_SYS_PTRACE should not be in any ring
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, Base), "CAP_SYS_PTRACE should not be in Base ring initially")
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should not be in EBPF ring initially")
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, Specific), "CAP_SYS_PTRACE should not be in Specific ring initially")

	// Add to Base ring (should propagate to all rings)
	err = caps.BaseRingAdd(cap.SYS_PTRACE)
	require.NoError(t, err)

	// Verify it's in ALL rings
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, Base), "CAP_SYS_PTRACE should be in Base ring after BaseRingAdd")
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should be in EBPF ring after BaseRingAdd")
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, Specific), "CAP_SYS_PTRACE should be in Specific ring after BaseRingAdd")
}

func TestCapabilities_EBPFRingRemove_StateUpdate(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	// Clean up any existing state from previous tests
	cleanupCapabilities(caps, cap.SYS_PTRACE)

	// First add the capability
	err = caps.EBPFRingAdd(cap.SYS_PTRACE)
	require.NoError(t, err)
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should be in EBPF ring after add")

	// Remove from EBPF ring
	err = caps.EBPFRingRemove(cap.SYS_PTRACE)
	require.NoError(t, err)

	// Verify it's removed from EBPF ring
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should not be in EBPF ring after EBPFRingRemove")
}

func TestCapabilities_BaseRingRemove_RemovesFromAllRings(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	// Clean up any existing state from previous tests
	cleanupCapabilities(caps, cap.SYS_PTRACE)

	// First add the capability to all rings
	err = caps.BaseRingAdd(cap.SYS_PTRACE)
	require.NoError(t, err)
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, Base), "CAP_SYS_PTRACE should be in Base ring after add")
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should be in EBPF ring after add")
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, Specific), "CAP_SYS_PTRACE should be in Specific ring after add")

	// Remove from Base ring (should remove from all rings)
	err = caps.BaseRingRemove(cap.SYS_PTRACE)
	require.NoError(t, err)

	// Verify it's removed from ALL rings
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, Base), "CAP_SYS_PTRACE should not be in Base ring after BaseRingRemove")
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should not be in EBPF ring after BaseRingRemove")
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, Specific), "CAP_SYS_PTRACE should not be in Specific ring after BaseRingRemove")
}

func TestCapabilities_Full_RingState(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	// Initially, capabilities should be in Full ring (set during initialization)
	assert.True(t, getCapabilityState(caps, cap.SYS_ADMIN, Full), "CAP_SYS_ADMIN should be in Full ring by default")

	// Use Full() which switches to Full ring, executes callback, then returns to Base
	capInFullDuringCallback := false
	capInBaseBeforeCallback := false
	capInBaseAfterCallback := false

	// Check Base ring before Full() - should be false (capabilities not in Base by default)
	capInBaseBeforeCallback = getCapabilityState(caps, cap.SYS_ADMIN, Base)

	// Full() switches to Full ring, executes callback, then returns to Base
	// Use getCapabilityStateUnsafe inside callback since lock is already held
	err = caps.Full(func() error {
		// During callback, Full ring should have the capability
		capInFullDuringCallback = getCapabilityStateUnsafe(caps, cap.SYS_ADMIN, Full)
		return nil
	})
	require.NoError(t, err)

	// Verify Full ring has the capability during callback
	assert.True(t, capInFullDuringCallback, "CAP_SYS_ADMIN should be in Full ring during callback")

	// After callback, check Base ring again
	capInBaseAfterCallback = getCapabilityState(caps, cap.SYS_ADMIN, Base)

	// Base ring should remain unchanged (Full() doesn't modify Base ring state)
	assert.Equal(t, capInBaseBeforeCallback, capInBaseAfterCallback, "Base ring state should not change after Full()")
}

func TestCapabilities_Specific_RingState(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	// Initially, CAP_SYS_ADMIN should not be in Specific ring
	assert.False(t, getCapabilityState(caps, cap.SYS_ADMIN, Specific), "CAP_SYS_ADMIN should not be in Specific ring initially")

	// Specific() sets, applies, unsets, then executes callback
	// Use getCapabilityStateUnsafe inside callback since lock is already held
	capInSpecificDuringCallback := false
	err = caps.Specific(func() error {
		// During callback, check if capability was in Specific ring
		// Note: Specific() unsets before callback, so it should be false
		capInSpecificDuringCallback = getCapabilityStateUnsafe(caps, cap.SYS_ADMIN, Specific)
		return nil
	}, cap.SYS_ADMIN)
	require.NoError(t, err)

	// Specific() unsets the capability before callback, so it should be false
	assert.False(t, capInSpecificDuringCallback, "CAP_SYS_ADMIN should not be in Specific ring during callback (unset before callback)")

	// After callback, should still be false
	assert.False(t, getCapabilityState(caps, cap.SYS_ADMIN, Specific), "CAP_SYS_ADMIN should not be in Specific ring after callback")
}

func TestCapabilities_MultipleCapabilities_StateUpdate(t *testing.T) {
	err := Initialize(Config{Bypass: true})
	require.NoError(t, err)

	caps := GetInstance()
	require.NotNil(t, caps)

	// Clean up any existing state from previous tests
	cleanupCapabilities(caps, cap.SYS_PTRACE, cap.SYS_ADMIN)

	// Add multiple capabilities to EBPF ring
	err = caps.EBPFRingAdd(cap.SYS_PTRACE, cap.SYS_ADMIN)
	require.NoError(t, err)

	// Verify both are in EBPF ring
	assert.True(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should be in EBPF ring")
	assert.True(t, getCapabilityState(caps, cap.SYS_ADMIN, EBPF), "CAP_SYS_ADMIN should be in EBPF ring")

	// Remove one
	err = caps.EBPFRingRemove(cap.SYS_PTRACE)
	require.NoError(t, err)

	// Verify one removed, one still present
	assert.False(t, getCapabilityState(caps, cap.SYS_PTRACE, EBPF), "CAP_SYS_PTRACE should not be in EBPF ring after remove")
	assert.True(t, getCapabilityState(caps, cap.SYS_ADMIN, EBPF), "CAP_SYS_ADMIN should still be in EBPF ring")
}

// getCapabilityState is a test helper that exposes the internal state for testing.
// It returns whether a capability is enabled for a given ring type.
//
// IMPORTANT: This function acquires a lock and should NOT be called from within
// callbacks passed to Full(), EBPF(), or Specific() methods, as those methods
// already hold the lock and Go mutexes are not re-entrant (would cause deadlock).
//
// Safe usage: Call between method invocations (e.g., after EBPFRingAdd() returns).
func getCapabilityState(c *Capabilities, capValue cap.Value, ring RingType) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	if m, exists := c.all[capValue]; exists {
		return m[ring]
	}
	return false
}

// getCapabilityStateUnsafe is a test helper that reads state WITHOUT locking.
// It should ONLY be called when the lock is already held (e.g., from within callbacks).
// This is safe because the caller already holds the lock, preventing concurrent modifications.
func getCapabilityStateUnsafe(c *Capabilities, capValue cap.Value, ring RingType) bool {
	if m, exists := c.all[capValue]; exists {
		return m[ring]
	}
	return false
}

// cleanupCapabilities removes the specified capabilities from all rings.
// This is a test helper to ensure clean state between tests (singleton pattern means state persists).
func cleanupCapabilities(c *Capabilities, values ...cap.Value) {
	for _, v := range values {
		_ = c.BaseRingRemove(v)
		_ = c.EBPFRingRemove(v)
	}
}
