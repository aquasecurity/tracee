package events

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
)

type CapDependencyTestCase struct {
	Name      string
	Caps      []cap.Value
	RingTypes []capabilities.RingType
}

// TestCapabilities_GetCaps tests the thread-safety of the GetCaps function.
func TestCapabilities_GetCaps_ThreadSafe(t *testing.T) {
	caps := NewCapabilities(map[capabilities.RingType][]cap.Value{
		capabilities.Base: {cap.SYSLOG, cap.SYS_PTRACE},
		capabilities.EBPF: {cap.AUDIT_CONTROL, cap.BLOCK_SUSPEND},
	})

	wg := &sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			capsBase := caps.GetCaps(capabilities.Base)
			capsEBPF := caps.GetCaps(capabilities.EBPF)
			require.ElementsMatch(t, capsBase, []cap.Value{cap.SYSLOG, cap.SYS_PTRACE})
			require.ElementsMatch(t, capsEBPF, []cap.Value{cap.AUDIT_CONTROL, cap.BLOCK_SUSPEND})
			wg.Done()
		}()
	}

	wg.Wait()
}

// TestCapabilities_Add_ThreadSafe tests the thread-safety of the Add functions.
func TestCapabilities_Add_ThreadSafe(t *testing.T) {
	caps := NewCapabilities(nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			caps.AddRingType(capabilities.Base)
			caps.AddCap(capabilities.Base, cap.SYSLOG)
			caps.AddCaps(capabilities.Base, []cap.Value{cap.SYSLOG, cap.AUDIT_CONTROL})
			capsBase := caps.GetCaps(capabilities.Base)
			// Testing for thread-safety. After 1st thread, the length of the slice should be 2.
			require.Equal(t, 2, len(capsBase)) // cap.SYSLOG and cap.AUDIT_CONTROL
			wg.Done()
		}()
	}

	wg.Wait()
}

// TestCapabilities_Remove_ThreadSafe tests the thread-safety of the Remove functions.
func TestCapabilities_Remove_ThreadSafe(t *testing.T) {
	caps := NewCapabilities(nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			caps.AddRingType(capabilities.EBPF)
			caps.RemoveRingType(capabilities.EBPF)
			caps.AddRingType(capabilities.Base)
			caps.AddCap(capabilities.Base, cap.SYSLOG)
			caps.AddCaps(capabilities.Base, []cap.Value{cap.SYSLOG, cap.AUDIT_CONTROL})
			caps.RemoveCap(capabilities.Base, cap.SYSLOG)
			caps.RemoveCaps(capabilities.Base, []cap.Value{cap.SYSLOG})
			wg.Done()
		}()
	}

	wg.Wait()

	// Testing for thread-safety more than correctness.
	require.Equal(t, 1, len(caps.GetCaps(capabilities.Base))) // cap.AUDIT_CONTROL
}

// TestCapabilities_Multiple_Capabilities_And_Rings tests multiple capabilities in multiple rings.
func TestCapabilities_Multiple_Capabilities_And_Rings(t *testing.T) {
	testCases := []CapDependencyTestCase{
		{
			Name: "Many capabilities in all Rings",
			Caps: []cap.Value{
				cap.AUDIT_CONTROL,
				cap.DAC_OVERRIDE,
				cap.SYSLOG,
				cap.SYS_ADMIN,
				cap.SYS_PTRACE,
				cap.LINUX_IMMUTABLE,
				cap.NET_ADMIN,
			},
			RingTypes: []capabilities.RingType{
				capabilities.Full,
				capabilities.EBPF,
				capabilities.Specific,
				capabilities.Base,
			},
		},
		{
			Name: "Specific capabilities in EPBF Ring",
			Caps: []cap.Value{
				cap.BPF,
				cap.SYSLOG,
				cap.SYS_ADMIN,
			},
			RingTypes: []capabilities.RingType{
				capabilities.EBPF,
			},
		},
		{
			Name: "No capabilities",
			Caps: []cap.Value{},
			RingTypes: []capabilities.RingType{
				capabilities.Full,
				capabilities.EBPF,
				capabilities.Specific,
				capabilities.Base,
			},
		},
	}
	for _, testCase := range testCases {
		c := NewCapabilities(nil)
		for _, ringType := range testCase.RingTypes {
			c.AddCaps(ringType, testCase.Caps)
		}
		for _, ringType := range testCase.RingTypes {
			assert.ElementsMatch(t, testCase.Caps, c.GetCaps(ringType))
		}
		for _, ringType := range testCase.RingTypes {
			c.RemoveCaps(ringType, testCase.Caps)
		}
		for _, ringType := range testCase.RingTypes {
			for _, t := range testCase.Caps {
				c.AddCap(ringType, t)
			}
		}
		for _, ringType := range testCase.RingTypes {
			assert.ElementsMatch(t, testCase.Caps, c.GetCaps(ringType))
		}
	}
}
