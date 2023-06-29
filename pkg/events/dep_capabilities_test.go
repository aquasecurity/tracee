package events

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
)

//
// Dependencies: Capabilities Tests
//

//
// NOTE:
//
// Within the Dependencies type, there is a single field which thread-safety is guaranteed by the
// field type itself, and not by Dependencies methods: Capabilities. Its thread-safety unit tests
// are in type_capabilities_test.go (and not this file).
//

var getFakeCapabilities = func() *Capabilities {
	return NewCapabilities(
		map[capabilities.RingType][]cap.Value{
			capabilities.Base: {
				cap.SYS_CHROOT,
				cap.SYS_PTRACE,
				cap.SYS_TIME,
			},
		},
	)
}

// TestDependencies_SetAndGetCapabilities_ThreadSafe tests Capabilities Get/Set atomicity.
func TestDependencies_SetAndGetCapabilities_ThreadSafe(t *testing.T) {
	d := NewDependencies(nil, nil, nil, nil, nil)

	wg := &sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			d.SetCapabilities(getFakeCapabilities())
			caps := d.GetCapabilities()
			require.NotNil(t, caps)
			require.Equal(t, 3, len(caps.GetCaps(capabilities.Base)))
			wg.Done()
		}()
	}

	wg.Wait()
}
