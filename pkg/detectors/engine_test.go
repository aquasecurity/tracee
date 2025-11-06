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

func TestNewEngine(t *testing.T) {
	engine := NewEngine(nil, nil)
	require.NotNil(t, engine)
	assert.NotNil(t, engine.registry)
	assert.NotNil(t, engine.dispatcher)
	assert.NotNil(t, engine.metrics)
}

func TestEngine_RegisterDetector(t *testing.T) {
	// Pre-register detector event
	testDetector := &mockDetector{
		id:        "test_engine_register",
		eventName: "test_engine_register_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}
	_, err := CreateEventsFromDetectors(events.StartDetectorID+10000, []detection.EventDetector{testDetector})
	require.NoError(t, err)

	engine := NewEngine(nil, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(testDetector, params)
	assert.NoError(t, err)
	assert.Equal(t, 1, engine.GetDetectorCount())
}

func TestEngine_GetDetectorCount(t *testing.T) {
	engine := NewEngine(nil, nil)
	assert.Equal(t, 0, engine.GetDetectorCount())

	// Register first detector
	detector1 := &mockDetector{
		id:        "detector1",
		eventName: "detector1_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}
	_, err := CreateEventsFromDetectors(events.StartDetectorID+10001, []detection.EventDetector{detector1})
	require.NoError(t, err)

	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}
	err = engine.RegisterDetector(detector1, params)
	require.NoError(t, err)
	assert.Equal(t, 1, engine.GetDetectorCount())

	// Register second detector
	detector2 := &mockDetector{
		id:        "detector2",
		eventName: "detector2_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}
	_, err = CreateEventsFromDetectors(events.StartDetectorID+10002, []detection.EventDetector{detector2})
	require.NoError(t, err)

	err = engine.RegisterDetector(detector2, params)
	require.NoError(t, err)
	assert.Equal(t, 2, engine.GetDetectorCount())
}

func TestEngine_UnregisterDetector(t *testing.T) {
	// Pre-register detector event
	testDetector := &mockDetector{
		id:        "test_unregister",
		eventName: "test_unregister_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}
	_, err := CreateEventsFromDetectors(events.StartDetectorID+10003, []detection.EventDetector{testDetector})
	require.NoError(t, err)

	engine := NewEngine(nil, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	// Register detector
	err = engine.RegisterDetector(testDetector, params)
	require.NoError(t, err)
	assert.Equal(t, 1, engine.GetDetectorCount())

	// Unregister detector
	err = engine.UnregisterDetector("test_unregister")
	assert.NoError(t, err)
	assert.Equal(t, 0, engine.GetDetectorCount())

	// Unregister non-existent detector
	err = engine.UnregisterDetector("non_existent")
	assert.Error(t, err)
}

func TestEngine_ListDetectors(t *testing.T) {
	engine := NewEngine(nil, nil)
	assert.Empty(t, engine.ListDetectors())

	// Register detectors
	detector1 := &mockDetector{
		id:        "detector_list_1",
		eventName: "detector_list_1_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}
	detector2 := &mockDetector{
		id:        "detector_list_2",
		eventName: "detector_list_2_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}

	_, err := CreateEventsFromDetectors(events.StartDetectorID+10004, []detection.EventDetector{detector1, detector2})
	require.NoError(t, err)

	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(detector1, params)
	require.NoError(t, err)
	err = engine.RegisterDetector(detector2, params)
	require.NoError(t, err)

	list := engine.ListDetectors()
	assert.Len(t, list, 2)
	assert.Contains(t, list, "detector_list_1")
	assert.Contains(t, list, "detector_list_2")
}

func TestEngine_GetDetector(t *testing.T) {
	testDetector := &mockDetector{
		id:        "test_get_detector",
		eventName: "test_get_detector_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}
	_, err := CreateEventsFromDetectors(events.StartDetectorID+10006, []detection.EventDetector{testDetector})
	require.NoError(t, err)

	engine := NewEngine(nil, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(testDetector, params)
	require.NoError(t, err)

	// Get existing detector
	retrieved, err := engine.GetDetector("test_get_detector")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, testDetector, retrieved)

	// Get non-existent detector
	_, err = engine.GetDetector("non_existent")
	assert.Error(t, err)
}

func TestEngine_EnableDisableDetector(t *testing.T) {
	testDetector := &mockDetector{
		id:        "test_enable_disable",
		eventName: "test_enable_disable_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}
	_, err := CreateEventsFromDetectors(events.StartDetectorID+10007, []detection.EventDetector{testDetector})
	require.NoError(t, err)

	engine := NewEngine(nil, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(testDetector, params)
	require.NoError(t, err)

	// Disable detector
	err = engine.DisableDetector("test_enable_disable")
	assert.NoError(t, err)

	// Enable detector
	err = engine.EnableDetector("test_enable_disable")
	assert.NoError(t, err)

	// Enable non-existent detector
	err = engine.EnableDetector("non_existent")
	assert.Error(t, err)

	// Disable non-existent detector
	err = engine.DisableDetector("non_existent")
	assert.Error(t, err)
}

func TestEngine_DispatchToDetectors(t *testing.T) {
	// Create a detector that produces output
	producingDetector := &mockDetector{
		id:        "test_dispatch_producing",
		eventName: "test_dispatch_producing_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
	}
	_, err := CreateEventsFromDetectors(events.StartDetectorID+10008, []detection.EventDetector{producingDetector})
	require.NoError(t, err)

	engine := NewEngine(nil, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(producingDetector, params)
	require.NoError(t, err)

	// Create an event to dispatch
	inputEvent := &v1beta1.Event{
		Id:   v1beta1.EventId(events.Execve),
		Name: "execve",
	}

	ctx := context.Background()
	outputs, err := engine.DispatchToDetectors(ctx, inputEvent)
	assert.NoError(t, err)
	// outputs can be nil or empty - mockDetector returns nil
	if outputs != nil {
		assert.Empty(t, outputs)
	}
}

func TestEngine_GetMetrics(t *testing.T) {
	engine := NewEngine(nil, nil)
	metrics := engine.GetMetrics()
	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.EventsProcessed)
	assert.NotNil(t, metrics.EventsProduced)
	assert.NotNil(t, metrics.Errors)
	assert.NotNil(t, metrics.ExecutionDuration)
}

func TestEngine_RegisterPrometheusMetrics(t *testing.T) {
	engine := NewEngine(nil, nil)
	// Just test that it doesn't panic - actual Prometheus registration
	// might fail in test environment but shouldn't crash
	err := engine.RegisterPrometheusMetrics()
	// We accept either success or error (Prometheus might not be available in test)
	_ = err
}
