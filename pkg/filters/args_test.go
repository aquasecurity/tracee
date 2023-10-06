package filters

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

func TestArgsFilterClone(t *testing.T) {
	t.Parallel()

	filter := NewArgFilter()
	err := filter.Parse("read.args.fd", "=argval", events.Core.NamesToIDs())
	require.NoError(t, err)

	copy := filter.Clone().(*ArgFilter)

	if !reflect.DeepEqual(filter, copy) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	err = copy.Parse("read.args.buf", "=argval", events.Core.NamesToIDs())
	require.NoError(t, err)
	if reflect.DeepEqual(filter, copy) {
		t.Errorf("Changes to copied filter affected the original")
	}
}
