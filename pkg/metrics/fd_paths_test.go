package metrics

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

func TestFDPathOutcomes(t *testing.T) {
	s := NewStats()
	for _, status := range []events.FDPathStatus{
		events.FDPathNone, events.FDPathResolved, events.FDPathUnavailable,
		events.FDPathUnavailable, events.FDPathReadError, events.FDPathStorageError,
		events.FDPathTruncated, 255,
	} {
		s.FDPaths.Observe(status)
	}
	b, err := json.Marshal(s.FDPaths)
	require.NoError(t, err)
	require.JSONEq(t, `{"Resolved":1,"Unavailable":2,"ReadError":1,"StorageError":1,"Truncated":1}`, string(b))
	require.Zero(t, s.ErrorCount.Get())
}
