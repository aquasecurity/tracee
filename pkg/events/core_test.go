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
