package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/events"
)

// mockDetectorForTags implements detection.EventDetector for testing tag registration
type mockDetectorForTags struct {
	id        string
	eventName string
	tags      []string
}

func (m *mockDetectorForTags) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: m.id,
		ProducedEvent: v1beta1.EventDefinition{
			Name:        m.eventName,
			Description: "Mock detector event",
			Tags:        m.tags,
		},
		Requirements: detection.DetectorRequirements{},
	}
}

func (m *mockDetectorForTags) Init(params detection.DetectorParams) error {
	return nil
}

func (m *mockDetectorForTags) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	return nil, nil
}

func createMockDetectorWithTags(id, eventName string, tags []string) detection.EventDetector {
	return &mockDetectorForTags{
		id:        id,
		eventName: eventName,
		tags:      tags,
	}
}

func TestDetectorTagsRegisteredAsSets(t *testing.T) {
	// Save the current state of events.Core and restore after test
	originalCore := events.Core
	defer func() { events.Core = originalCore }()

	// Create a fresh DefinitionGroup for this test
	events.Core = events.NewDefinitionGroup()
	// Add core events that tests might depend on
	err := events.Core.AddBatch(events.CoreEvents)
	require.NoError(t, err)

	// Create mock detectors with different tags
	mockDetectors := []detection.EventDetector{
		createMockDetectorWithTags("detector1", "test_event1", []string{"containers", "security"}),
		createMockDetectorWithTags("detector2", "test_event2", []string{"malware"}),
		createMockDetectorWithTags("detector3", "test_event3", []string{"containers"}),
		createMockDetectorWithTags("detector4", "test_event4", []string{}), // No tags
	}

	// Register events
	eventMap, err := CreateEventsFromDetectors(events.StartDetectorID, mockDetectors)
	require.NoError(t, err)
	require.Equal(t, 4, len(eventMap), "Should have registered 4 events")

	// Verify tags are in event sets
	for eventName, eventID := range eventMap {
		def := events.Core.GetDefinitionByID(eventID)
		require.NotEqual(t, events.Undefined, def.GetID(), "Event definition should exist for %s", eventName)

		sets := def.GetSets()

		// All should have "detectors" and "default"
		assert.Contains(t, sets, "detectors", "Event %s should have 'detectors' set", eventName)
		assert.Contains(t, sets, "default", "Event %s should have 'default' set", eventName)

		// Verify detector-specific tags based on setup
		switch eventName {
		case "test_event1":
			assert.Contains(t, sets, "containers", "Event %s should have 'containers' tag", eventName)
			assert.Contains(t, sets, "security", "Event %s should have 'security' tag", eventName)
			assert.Equal(t, 4, len(sets), "Event %s should have 4 sets total", eventName)
		case "test_event2":
			assert.Contains(t, sets, "malware", "Event %s should have 'malware' tag", eventName)
			assert.Equal(t, 3, len(sets), "Event %s should have 3 sets total", eventName)
		case "test_event3":
			assert.Contains(t, sets, "containers", "Event %s should have 'containers' tag", eventName)
			assert.Equal(t, 3, len(sets), "Event %s should have 3 sets total", eventName)
		case "test_event4":
			assert.Equal(t, 2, len(sets), "Event %s should have only 2 sets (no custom tags)", eventName)
		}
	}

	// Verify set-based lookup works
	containerEvents := findEventsBySet("containers", eventMap)
	assert.Contains(t, containerEvents, "test_event1", "containers set should include test_event1")
	assert.Contains(t, containerEvents, "test_event3", "containers set should include test_event3")
	assert.NotContains(t, containerEvents, "test_event2", "containers set should not include test_event2")
	assert.NotContains(t, containerEvents, "test_event4", "containers set should not include test_event4")

	malwareEvents := findEventsBySet("malware", eventMap)
	assert.Contains(t, malwareEvents, "test_event2", "malware set should include test_event2")
	assert.NotContains(t, malwareEvents, "test_event1", "malware set should not include test_event1")
	assert.NotContains(t, malwareEvents, "test_event3", "malware set should not include test_event3")

	securityEvents := findEventsBySet("security", eventMap)
	assert.Contains(t, securityEvents, "test_event1", "security set should include test_event1")
	assert.NotContains(t, securityEvents, "test_event2", "security set should not include test_event2")
}

// findEventsBySet returns event names that belong to a given set
func findEventsBySet(setName string, eventMap map[string]events.ID) []string {
	var result []string
	for eventName, eventID := range eventMap {
		def := events.Core.GetDefinitionByID(eventID)
		// Check if definition was found (id != Undefined)
		if def.GetID() == events.Undefined {
			continue
		}
		for _, set := range def.GetSets() {
			if set == setName {
				result = append(result, eventName)
				break
			}
		}
	}
	return result
}

func TestDetectorTagsWithMultipleTags(t *testing.T) {
	// Save the current state and restore after test
	originalCore := events.Core
	defer func() { events.Core = originalCore }()

	events.Core = events.NewDefinitionGroup()
	err := events.Core.AddBatch(events.CoreEvents)
	require.NoError(t, err)

	// Test detector with multiple tags
	mockDetectors := []detection.EventDetector{
		createMockDetectorWithTags("multi_tag_detector", "multi_tag_event", []string{"tag1", "tag2", "tag3"}),
	}

	eventMap, err := CreateEventsFromDetectors(events.StartDetectorID, mockDetectors)
	require.NoError(t, err)
	require.Equal(t, 1, len(eventMap))

	eventID := eventMap["multi_tag_event"]
	def := events.Core.GetDefinitionByID(eventID)
	require.NotEqual(t, events.Undefined, def.GetID(), "Event definition should exist")

	sets := def.GetSets()
	// Should have: detectors, default, tag1, tag2, tag3 = 5 sets
	assert.Equal(t, 5, len(sets))
	assert.Contains(t, sets, "detectors")
	assert.Contains(t, sets, "default")
	assert.Contains(t, sets, "tag1")
	assert.Contains(t, sets, "tag2")
	assert.Contains(t, sets, "tag3")

	// Verify each tag can find the event
	for _, tag := range []string{"tag1", "tag2", "tag3"} {
		foundEvents := findEventsBySet(tag, eventMap)
		assert.Contains(t, foundEvents, "multi_tag_event", "Tag %s should find the event", tag)
	}
}
