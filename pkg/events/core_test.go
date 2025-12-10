package events

import (
	"fmt"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
)

func TestAllEventsHaveVersion(t *testing.T) {
	t.Parallel()

	for _, event := range CoreEvents {
		_, err := semver.StrictNewVersion(event.version.String())
		assert.NoError(t, err, fmt.Sprintf("event %s has invalid version", event.name))
	}
}

func TestLookupPredefinedEventID(t *testing.T) {
	t.Parallel()

	t.Run("finds existing events", func(t *testing.T) {
		// Test with some known core events
		id := LookupPredefinedEventID("sched_process_exec")
		assert.NotEqual(t, ID(0), id, "sched_process_exec should be found")

		id = LookupPredefinedEventID("security_file_open")
		assert.NotEqual(t, ID(0), id, "security_file_open should be found")
	})

	t.Run("returns 0 for non-existent event", func(t *testing.T) {
		id := LookupPredefinedEventID("non_existent_event_xyz")
		assert.Equal(t, ID(0), id, "non-existent event should return 0")
	})

	t.Run("returns 0 for empty string", func(t *testing.T) {
		id := LookupPredefinedEventID("")
		assert.Equal(t, ID(0), id, "empty string should return 0")
	})

	t.Run("case sensitive", func(t *testing.T) {
		// Event names should be case-sensitive
		id1 := LookupPredefinedEventID("sched_process_exec")
		id2 := LookupPredefinedEventID("SCHED_PROCESS_EXEC")
		assert.NotEqual(t, id1, id2, "lookup should be case-sensitive")
		assert.Equal(t, ID(0), id2, "uppercase version should not be found")
	})
}
