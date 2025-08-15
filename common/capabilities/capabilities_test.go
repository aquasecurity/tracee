package capabilities

import (
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
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
