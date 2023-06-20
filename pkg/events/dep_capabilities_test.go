package events

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
)

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
