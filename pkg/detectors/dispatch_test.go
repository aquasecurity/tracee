package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/datastores"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// Helper function to create a test policy manager that selects specific events
func newTestPolicyManager(selectedEventIDs ...events.ID) *policy.Manager {
	// Create a dependencies manager
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	// Create policy manager with no initial policies
	policyMgr, err := policy.NewManager(policy.ManagerConfig{}, depsManager)
	if err != nil {
		panic(err)
	}

	// Enable the specified events
	for _, eventID := range selectedEventIDs {
		policyMgr.EnableEvent(eventID)
	}

	return policyMgr
}

// Helper function to create a test process tree
func newTestProcessTree(ctx context.Context) (*process.ProcessTree, error) {
	return process.NewProcessTree(ctx, process.ProcTreeConfig{
		Source:           process.SourceNone,
		ProcessCacheSize: 100,
		ThreadCacheSize:  100,
	})
}

// Helper function to create a test datastore registry
func newTestDataStoreRegistry() *datastores.Registry {
	return datastores.NewRegistry()
}

// producingDetector is a mock detector that actually produces events
type producingDetector struct {
	id             string
	eventName      string
	threatMetadata *v1beta1.Threat
	autoPopulate   detection.AutoPopulateFields
	requirements   detection.DetectorRequirements
	outputEvent    *v1beta1.Event
}

func (d *producingDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID:             d.id,
		Requirements:   d.requirements,
		ProducedEvent:  v1beta1.EventDefinition{Name: d.eventName},
		ThreatMetadata: d.threatMetadata,
		AutoPopulate:   d.autoPopulate,
	}
}

func (d *producingDetector) Init(params detection.DetectorParams) error {
	return nil
}

func (d *producingDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	if d.outputEvent != nil {
		return []detection.DetectorOutput{{Data: d.outputEvent.Data}}, nil
	}
	// Create a simple output
	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *producingDetector) Close() error {
	return nil
}

func TestDispatchToDetectors_WithOutput(t *testing.T) {
	// Create a detector that produces output
	detector := &producingDetector{
		id:        "test_dispatch_output",
		eventName: "test_dispatch_output_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
		autoPopulate: detection.AutoPopulateFields{},
	}

	_, err := CreateEventsFromDetectors(events.StartDetectorID+20000, []detection.EventDetector{detector})
	require.NoError(t, err)

	// Create test policy manager that selects the detector's output event
	detEventID, _ := events.Core.GetDefinitionIDByName(detector.eventName)
	policyMgr := newTestPolicyManager(detEventID)

	engine := NewEngine(policyMgr, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(detector, params)
	require.NoError(t, err)

	// Enable the detector
	err = engine.EnableDetector(detector.id)
	require.NoError(t, err)

	// Create an input event
	inputEvent := &v1beta1.Event{
		Id:   v1beta1.EventId(events.Execve),
		Name: "execve",
	}

	ctx := context.Background()
	outputs, err := engine.DispatchToDetectors(ctx, inputEvent)
	assert.NoError(t, err)
	assert.NotNil(t, outputs)
	assert.Len(t, outputs, 1)

	// Verify output event has ID and name assigned by engine
	assert.NotEqual(t, v1beta1.EventId(0), outputs[0].Id)
	assert.Equal(t, "test_dispatch_output_event", outputs[0].Name)
}

func TestAutoPopulateFields_Threat(t *testing.T) {
	threatMetadata := &v1beta1.Threat{
		Name:        "Test Threat",
		Description: "Test threat description",
		Severity:    v1beta1.Severity_HIGH,
		Mitre: &v1beta1.Mitre{
			Tactic: &v1beta1.MitreTactic{
				Name: "Defense Evasion",
			},
			Technique: &v1beta1.MitreTechnique{
				Id:   "T1055",
				Name: "Process Injection",
			},
		},
		Properties: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	detector := &producingDetector{
		id:        "test_autopop_threat",
		eventName: "test_autopop_threat_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
		threatMetadata: threatMetadata,
		autoPopulate: detection.AutoPopulateFields{
			Threat: true, // Enable threat auto-population
		},
	}

	_, err := CreateEventsFromDetectors(events.StartDetectorID+20001, []detection.EventDetector{detector})
	require.NoError(t, err)

	// Create test policy manager that selects the detector's output event
	detEventID, _ := events.Core.GetDefinitionIDByName(detector.eventName)
	policyMgr := newTestPolicyManager(detEventID)

	engine := NewEngine(policyMgr, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(detector, params)
	require.NoError(t, err)

	// Enable the detector
	err = engine.EnableDetector(detector.id)
	require.NoError(t, err)

	// Create input event
	inputEvent := &v1beta1.Event{
		Id:   v1beta1.EventId(events.Execve),
		Name: "execve",
	}

	ctx := context.Background()
	outputs, err := engine.DispatchToDetectors(ctx, inputEvent)
	assert.NoError(t, err)
	require.Len(t, outputs, 1)

	// Verify threat was auto-populated
	output := outputs[0]
	require.NotNil(t, output.Threat)
	assert.Equal(t, "Test Threat", output.Threat.Name)
	assert.Equal(t, "Test threat description", output.Threat.Description)
	assert.Equal(t, v1beta1.Severity_HIGH, output.Threat.Severity)

	// Verify MITRE data was cloned
	require.NotNil(t, output.Threat.Mitre)
	require.NotNil(t, output.Threat.Mitre.Tactic)
	assert.Equal(t, "Defense Evasion", output.Threat.Mitre.Tactic.Name)
	require.NotNil(t, output.Threat.Mitre.Technique)
	assert.Equal(t, "T1055", output.Threat.Mitre.Technique.Id)
	assert.Equal(t, "Process Injection", output.Threat.Mitre.Technique.Name)

	// Verify properties were cloned
	assert.Equal(t, "value1", output.Threat.Properties["key1"])
	assert.Equal(t, "value2", output.Threat.Properties["key2"])

	// Verify it's a deep clone (modifying output shouldn't affect original)
	output.Threat.Properties["key1"] = "modified"
	assert.Equal(t, "value1", threatMetadata.Properties["key1"])
}

func TestAutoPopulateFields_DetectedFrom(t *testing.T) {
	detector := &producingDetector{
		id:        "test_autopop_detectedfrom",
		eventName: "test_autopop_detectedfrom_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
		autoPopulate: detection.AutoPopulateFields{
			DetectedFrom: true, // Enable DetectedFrom auto-population
		},
	}

	_, err := CreateEventsFromDetectors(events.StartDetectorID+20002, []detection.EventDetector{detector})
	require.NoError(t, err)

	// Create test policy manager that selects the detector's output event
	detEventID, _ := events.Core.GetDefinitionIDByName(detector.eventName)
	policyMgr := newTestPolicyManager(detEventID)

	engine := NewEngine(policyMgr, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(detector, params)
	require.NoError(t, err)

	// Enable the detector
	err = engine.EnableDetector(detector.id)
	require.NoError(t, err)

	// Create input event with data
	inputEvent := &v1beta1.Event{
		Id:   v1beta1.EventId(events.Execve),
		Name: "execve",
		Data: []*v1beta1.EventValue{
			{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/bin/bash"}},
			{Name: "pid", Value: &v1beta1.EventValue_Int32{Int32: 1234}},
		},
	}

	ctx := context.Background()
	outputs, err := engine.DispatchToDetectors(ctx, inputEvent)
	assert.NoError(t, err)
	require.Len(t, outputs, 1)

	// Verify DetectedFrom was auto-populated
	output := outputs[0]
	require.NotNil(t, output.DetectedFrom)
	assert.Equal(t, uint32(events.Execve), output.DetectedFrom.Id)
	assert.Equal(t, "execve", output.DetectedFrom.Name)

	// Verify event data was copied
	require.Len(t, output.DetectedFrom.Data, 2)
	assert.Equal(t, "pathname", output.DetectedFrom.Data[0].Name)
	assert.Equal(t, "pid", output.DetectedFrom.Data[1].Name)
}

func TestAutoPopulateFields_Combined(t *testing.T) {
	detector := &producingDetector{
		id:        "test_autopop_combined",
		eventName: "test_autopop_combined_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
		threatMetadata: &v1beta1.Threat{
			Name:     "Combined Test",
			Severity: v1beta1.Severity_MEDIUM,
		},
		autoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}

	_, err := CreateEventsFromDetectors(events.StartDetectorID+20003, []detection.EventDetector{detector})
	require.NoError(t, err)

	// Create test policy manager that selects the detector's output event
	detEventID, _ := events.Core.GetDefinitionIDByName(detector.eventName)
	policyMgr := newTestPolicyManager(detEventID)

	engine := NewEngine(policyMgr, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(detector, params)
	require.NoError(t, err)

	// Enable the detector
	err = engine.EnableDetector(detector.id)
	require.NoError(t, err)

	inputEvent := &v1beta1.Event{
		Id:   v1beta1.EventId(events.Execve),
		Name: "execve",
	}

	ctx := context.Background()
	outputs, err := engine.DispatchToDetectors(ctx, inputEvent)
	assert.NoError(t, err)
	require.Len(t, outputs, 1)

	// Verify both fields were auto-populated
	output := outputs[0]
	assert.NotNil(t, output.Threat)
	assert.Equal(t, "Combined Test", output.Threat.Name)
	assert.NotNil(t, output.DetectedFrom)
	assert.Equal(t, "execve", output.DetectedFrom.Name)
}

func TestCloneThreat(t *testing.T) {
	original := &v1beta1.Threat{
		Name:        "Original Threat",
		Description: "Original description",
		Severity:    v1beta1.Severity_CRITICAL,
		Mitre: &v1beta1.Mitre{
			Tactic: &v1beta1.MitreTactic{
				Name: "Initial Access",
			},
			Technique: &v1beta1.MitreTechnique{
				Id:   "T1190",
				Name: "Exploit Public-Facing Application",
			},
		},
		Properties: map[string]string{
			"prop1": "value1",
			"prop2": "value2",
		},
	}

	cloned := cloneThreat(original)

	// Verify all fields were cloned
	assert.Equal(t, original.Name, cloned.Name)
	assert.Equal(t, original.Description, cloned.Description)
	assert.Equal(t, original.Severity, cloned.Severity)

	// Verify MITRE data was cloned
	require.NotNil(t, cloned.Mitre)
	require.NotNil(t, cloned.Mitre.Tactic)
	assert.Equal(t, original.Mitre.Tactic.Name, cloned.Mitre.Tactic.Name)
	require.NotNil(t, cloned.Mitre.Technique)
	assert.Equal(t, original.Mitre.Technique.Id, cloned.Mitre.Technique.Id)
	assert.Equal(t, original.Mitre.Technique.Name, cloned.Mitre.Technique.Name)

	// Verify properties map was cloned
	assert.Equal(t, original.Properties["prop1"], cloned.Properties["prop1"])
	assert.Equal(t, original.Properties["prop2"], cloned.Properties["prop2"])

	// Verify deep clone (modifying clone doesn't affect original)
	cloned.Name = "Modified"
	cloned.Mitre.Tactic.Name = "Modified Tactic"
	cloned.Properties["prop1"] = "modified"

	assert.Equal(t, "Original Threat", original.Name)
	assert.Equal(t, "Initial Access", original.Mitre.Tactic.Name)
	assert.Equal(t, "value1", original.Properties["prop1"])
}

func TestCloneThreat_Nil(t *testing.T) {
	cloned := cloneThreat(nil)
	assert.Nil(t, cloned)
}

func TestCloneThreat_NilMitre(t *testing.T) {
	original := &v1beta1.Threat{
		Name:     "Threat without MITRE",
		Severity: v1beta1.Severity_LOW,
		Mitre:    nil,
	}

	cloned := cloneThreat(original)
	assert.NotNil(t, cloned)
	assert.Equal(t, original.Name, cloned.Name)
	assert.Nil(t, cloned.Mitre)
}

func TestCloneMitreTactic_Nil(t *testing.T) {
	cloned := cloneMitreTactic(nil)
	assert.Nil(t, cloned)
}

func TestCloneMitreTechnique_Nil(t *testing.T) {
	cloned := cloneMitreTechnique(nil)
	assert.Nil(t, cloned)
}

func TestDispatchWithScopeFilter(t *testing.T) {
	detector := &producingDetector{
		id:        "test_scope_dispatch",
		eventName: "test_scope_dispatch_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "execve",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container"},
				},
			},
		},
		autoPopulate: detection.AutoPopulateFields{},
	}

	_, err := CreateEventsFromDetectors(events.StartDetectorID+20004, []detection.EventDetector{detector})
	require.NoError(t, err)

	// Create test policy manager that selects the detector's output event
	detEventID, _ := events.Core.GetDefinitionIDByName(detector.eventName)
	policyMgr := newTestPolicyManager(detEventID)

	engine := NewEngine(policyMgr, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(detector, params)
	require.NoError(t, err)

	// Enable the detector
	err = engine.EnableDetector(detector.id)
	require.NoError(t, err)

	// Test with host event (should be filtered out)
	hostEvent := &v1beta1.Event{
		Id:   v1beta1.EventId(events.Execve),
		Name: "execve",
		Workload: &v1beta1.Workload{
			Container: nil, // No container = host
		},
	}

	ctx := context.Background()
	outputs, err := engine.DispatchToDetectors(ctx, hostEvent)
	assert.NoError(t, err)
	assert.Empty(t, outputs) // Should be filtered out

	// Test with container event (should pass through)
	containerEvent := &v1beta1.Event{
		Id:   v1beta1.EventId(events.Execve),
		Name: "execve",
		Workload: &v1beta1.Workload{
			Container: &v1beta1.Container{
				Id: "container123",
			},
		},
	}

	outputs, err = engine.DispatchToDetectors(ctx, containerEvent)
	assert.NoError(t, err)
	assert.Len(t, outputs, 1) // Should pass through filter
}

func TestCollectAllDetectors(t *testing.T) {
	// CollectAllDetectors gathers detectors from built-in sources
	// Since we can't easily mock the builtin module, we just verify it doesn't panic
	// and returns a slice (could be empty in test environment)
	detectors := CollectAllDetectors(nil) // Pass nil to use default paths
	assert.NotNil(t, detectors)
	// The slice might be empty if no detectors are registered in init()
}

func TestAutoPopulateFields_ProcessAncestry(t *testing.T) {
	// Setup: Create process tree with ancestry
	ctx := context.Background()
	pt, err := newTestProcessTree(ctx)
	require.NoError(t, err)

	// Create process hierarchy: init (100) -> bash (200) -> python (300)
	initProc := pt.GetOrCreateProcessByHash(100)
	initFeed := &process.TaskInfoFeed{
		Pid:    1,
		NsPid:  1,
		PPid:   0,
		NsPPid: 0,
		Name:   "init",
	}
	initProc.GetInfo().SetFeed(initFeed)
	initProc.SetParentHash(0)

	bashProc := pt.GetOrCreateProcessByHash(200)
	bashFeed := &process.TaskInfoFeed{
		Pid:    1000,
		NsPid:  1,
		PPid:   1,
		NsPPid: 1,
		Name:   "bash",
	}
	bashProc.GetInfo().SetFeed(bashFeed)
	bashProc.SetParentHash(100)

	pythonProc := pt.GetOrCreateProcessByHash(300)
	pythonFeed := &process.TaskInfoFeed{
		Pid:    2000,
		NsPid:  100,
		PPid:   1000,
		NsPPid: 1,
		Name:   "python",
	}
	pythonProc.GetInfo().SetFeed(pythonFeed)
	pythonProc.SetParentHash(200)

	// Create detector with ProcessAncestry enabled
	detector := &producingDetector{
		id:        "test_autopop_ancestry",
		eventName: "test_autopop_ancestry_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
		autoPopulate: detection.AutoPopulateFields{
			ProcessAncestry: true, // Enable ancestry auto-population
		},
	}

	_, err = CreateEventsFromDetectors(events.StartDetectorID+20005, []detection.EventDetector{detector})
	require.NoError(t, err)

	// Create test policy manager
	detEventID, _ := events.Core.GetDefinitionIDByName(detector.eventName)
	policyMgr := newTestPolicyManager(detEventID)

	engine := NewEngine(policyMgr, nil)

	// Create a registry with process store for testing
	reg := newTestDataStoreRegistry()
	err = reg.RegisterStore("process", pt, true)
	require.NoError(t, err)

	params := detection.DetectorParams{
		Config:     detection.NewEmptyDetectorConfig(),
		DataStores: reg,
	}

	err = engine.RegisterDetector(detector, params)
	require.NoError(t, err)

	// Enable the detector
	err = engine.EnableDetector(detector.id)
	require.NoError(t, err)

	// Create input event from python process
	inputEvent := &v1beta1.Event{
		Id:   v1beta1.EventId(events.Execve),
		Name: "execve",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				UniqueId: &wrapperspb.UInt32Value{Value: 300},
			},
		},
	}

	outputs, err := engine.DispatchToDetectors(ctx, inputEvent)
	assert.NoError(t, err)
	require.Len(t, outputs, 1)

	// Verify ancestry was populated
	output := outputs[0]
	require.NotNil(t, output.Workload)
	require.NotNil(t, output.Workload.Process)
	require.NotNil(t, output.Workload.Process.Ancestors)
	assert.Len(t, output.Workload.Process.Ancestors, 2) // bash + init

	// Check bash (first ancestor)
	bash := output.Workload.Process.Ancestors[0]
	assert.Equal(t, uint32(200), bash.UniqueId.GetValue())
	assert.Equal(t, uint32(1000), bash.HostPid.GetValue())
	assert.Equal(t, uint32(1), bash.Pid.GetValue()) // VERIFY: namespace PID

	// Check init (second ancestor)
	init := output.Workload.Process.Ancestors[1]
	assert.Equal(t, uint32(100), init.UniqueId.GetValue())
	assert.Equal(t, uint32(1), init.HostPid.GetValue())
	assert.Equal(t, uint32(1), init.Pid.GetValue()) // Same for init
}

// TestAutoPopulateFields_DetectedFrom_ChainPreservation tests that detection chains are preserved
func TestAutoPopulateFields_DetectedFrom_ChainPreservation(t *testing.T) {
	t.Run("single level chain preserved", func(t *testing.T) {
		// Create first-level detector
		detector1 := &producingDetector{
			id:        "test_chain_level1",
			eventName: "test_chain_level1_event",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "execve", Dependency: detection.DependencyRequired},
				},
			},
			autoPopulate: detection.AutoPopulateFields{
				DetectedFrom: true,
			},
		}

		// Create second-level detector that consumes first detector's output
		detector2 := &producingDetector{
			id:        "test_chain_level2",
			eventName: "test_chain_level2_event",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "test_chain_level1_event", Dependency: detection.DependencyRequired},
				},
			},
			autoPopulate: detection.AutoPopulateFields{
				DetectedFrom: true,
			},
		}

		// Register both detectors
		_, err := CreateEventsFromDetectors(events.StartDetectorID+30001, []detection.EventDetector{detector1, detector2})
		require.NoError(t, err)

		det1EventID, _ := events.Core.GetDefinitionIDByName(detector1.eventName)
		det2EventID, _ := events.Core.GetDefinitionIDByName(detector2.eventName)
		policyMgr := newTestPolicyManager(det1EventID, det2EventID)

		engine := NewEngine(policyMgr, nil)
		params := detection.DetectorParams{
			Config: detection.NewEmptyDetectorConfig(),
		}

		err = engine.RegisterDetector(detector1, params)
		require.NoError(t, err)
		err = engine.RegisterDetector(detector2, params)
		require.NoError(t, err)

		err = engine.EnableDetector(detector1.id)
		require.NoError(t, err)
		err = engine.EnableDetector(detector2.id)
		require.NoError(t, err)

		// Create base event (execve)
		baseEvent := &v1beta1.Event{
			Id:   v1beta1.EventId(events.Execve),
			Name: "execve",
			Data: []*v1beta1.EventValue{
				{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/bin/bash"}},
			},
		}

		ctx := context.Background()

		// First dispatch: execve -> detector1
		outputs1, err := engine.DispatchToDetectors(ctx, baseEvent)
		assert.NoError(t, err)
		require.Len(t, outputs1, 1)

		// Verify first level has DetectedFrom pointing to execve
		level1Event := outputs1[0]
		require.NotNil(t, level1Event.DetectedFrom)
		assert.Equal(t, uint32(events.Execve), level1Event.DetectedFrom.Id)
		assert.Equal(t, "execve", level1Event.DetectedFrom.Name)
		assert.Nil(t, level1Event.DetectedFrom.Parent) // No parent yet

		// Second dispatch: detector1 output -> detector2
		outputs2, err := engine.DispatchToDetectors(ctx, level1Event)
		assert.NoError(t, err)
		require.Len(t, outputs2, 1)

		// Verify second level has chained DetectedFrom
		level2Event := outputs2[0]
		require.NotNil(t, level2Event.DetectedFrom)
		assert.Equal(t, uint32(det1EventID), level2Event.DetectedFrom.Id)
		assert.Equal(t, "test_chain_level1_event", level2Event.DetectedFrom.Name)

		// Critical: Verify parent chain was preserved
		require.NotNil(t, level2Event.DetectedFrom.Parent, "Parent chain should be preserved")
		assert.Equal(t, uint32(events.Execve), level2Event.DetectedFrom.Parent.Id)
		assert.Equal(t, "execve", level2Event.DetectedFrom.Parent.Name)
	})

	t.Run("three level chain preserved", func(t *testing.T) {
		// Create three chained detectors
		detector1 := &producingDetector{
			id:        "test_3level_det1",
			eventName: "test_3level_event1",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "execve", Dependency: detection.DependencyRequired},
				},
			},
			autoPopulate: detection.AutoPopulateFields{DetectedFrom: true},
		}

		detector2 := &producingDetector{
			id:        "test_3level_det2",
			eventName: "test_3level_event2",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "test_3level_event1", Dependency: detection.DependencyRequired},
				},
			},
			autoPopulate: detection.AutoPopulateFields{DetectedFrom: true},
		}

		detector3 := &producingDetector{
			id:        "test_3level_det3",
			eventName: "test_3level_event3",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "test_3level_event2", Dependency: detection.DependencyRequired},
				},
			},
			autoPopulate: detection.AutoPopulateFields{DetectedFrom: true},
		}

		// Register all three detectors
		_, err := CreateEventsFromDetectors(events.StartDetectorID+30100, []detection.EventDetector{detector1, detector2, detector3})
		require.NoError(t, err)

		det1EventID, _ := events.Core.GetDefinitionIDByName(detector1.eventName)
		det2EventID, _ := events.Core.GetDefinitionIDByName(detector2.eventName)
		det3EventID, _ := events.Core.GetDefinitionIDByName(detector3.eventName)
		policyMgr := newTestPolicyManager(det1EventID, det2EventID, det3EventID)

		engine := NewEngine(policyMgr, nil)
		params := detection.DetectorParams{
			Config: detection.NewEmptyDetectorConfig(),
		}

		for _, det := range []detection.EventDetector{detector1, detector2, detector3} {
			err = engine.RegisterDetector(det, params)
			require.NoError(t, err)
			err = engine.EnableDetector(det.GetDefinition().ID)
			require.NoError(t, err)
		}

		ctx := context.Background()

		// Level 0: Base event
		baseEvent := &v1beta1.Event{
			Id:   v1beta1.EventId(events.Execve),
			Name: "execve",
			Data: []*v1beta1.EventValue{
				{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/usr/bin/nc"}},
			},
		}

		// Level 1: execve -> detector1
		outputs1, err := engine.DispatchToDetectors(ctx, baseEvent)
		assert.NoError(t, err)
		require.Len(t, outputs1, 1)
		level1Event := outputs1[0]

		// Level 2: detector1 -> detector2
		outputs2, err := engine.DispatchToDetectors(ctx, level1Event)
		assert.NoError(t, err)
		require.Len(t, outputs2, 1)
		level2Event := outputs2[0]

		// Level 3: detector2 -> detector3
		outputs3, err := engine.DispatchToDetectors(ctx, level2Event)
		assert.NoError(t, err)
		require.Len(t, outputs3, 1)
		level3Event := outputs3[0]

		// Verify full 3-level chain
		require.NotNil(t, level3Event.DetectedFrom, "Level 3 should have DetectedFrom")
		assert.Equal(t, uint32(det2EventID), level3Event.DetectedFrom.Id)

		require.NotNil(t, level3Event.DetectedFrom.Parent, "Level 3 should have parent")
		assert.Equal(t, uint32(det1EventID), level3Event.DetectedFrom.Parent.Id)

		require.NotNil(t, level3Event.DetectedFrom.Parent.Parent, "Level 3 should have grandparent")
		assert.Equal(t, uint32(events.Execve), level3Event.DetectedFrom.Parent.Parent.Id)
		assert.Equal(t, "execve", level3Event.DetectedFrom.Parent.Parent.Name)

		// Verify we can use the helper functions
		chain := v1beta1.GetDetectionChain(level3Event)
		assert.Len(t, chain, 3)

		root := v1beta1.GetRootDetection(level3Event)
		assert.Equal(t, uint32(events.Execve), root.Id)

		depth := v1beta1.GetChainDepth(level3Event)
		assert.Equal(t, 3, depth)
	})

	t.Run("chain with data preservation", func(t *testing.T) {
		// Verify that data is preserved at each level of the chain
		detector1 := &producingDetector{
			id:        "test_data_chain1",
			eventName: "test_data_chain1_event",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "execve", Dependency: detection.DependencyRequired},
				},
			},
			autoPopulate: detection.AutoPopulateFields{DetectedFrom: true},
		}

		detector2 := &producingDetector{
			id:        "test_data_chain2",
			eventName: "test_data_chain2_event",
			requirements: detection.DetectorRequirements{
				Events: []detection.EventRequirement{
					{Name: "test_data_chain1_event", Dependency: detection.DependencyRequired},
				},
			},
			autoPopulate: detection.AutoPopulateFields{DetectedFrom: true},
			outputEvent: &v1beta1.Event{
				Data: []*v1beta1.EventValue{
					{Name: "severity", Value: &v1beta1.EventValue_Str{Str: "high"}},
				},
			},
		}

		_, err := CreateEventsFromDetectors(events.StartDetectorID+30200, []detection.EventDetector{detector1, detector2})
		require.NoError(t, err)

		det1EventID, _ := events.Core.GetDefinitionIDByName(detector1.eventName)
		det2EventID, _ := events.Core.GetDefinitionIDByName(detector2.eventName)
		policyMgr := newTestPolicyManager(det1EventID, det2EventID)

		engine := NewEngine(policyMgr, nil)
		params := detection.DetectorParams{
			Config: detection.NewEmptyDetectorConfig(),
		}

		for _, det := range []detection.EventDetector{detector1, detector2} {
			err = engine.RegisterDetector(det, params)
			require.NoError(t, err)
			err = engine.EnableDetector(det.GetDefinition().ID)
			require.NoError(t, err)
		}

		ctx := context.Background()

		// Base event with data
		baseEvent := &v1beta1.Event{
			Id:   v1beta1.EventId(events.Execve),
			Name: "execve",
			Data: []*v1beta1.EventValue{
				{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/bin/nc"}},
				{Name: "pid", Value: &v1beta1.EventValue_Int32{Int32: 1234}},
			},
		}

		// Dispatch through chain
		outputs1, err := engine.DispatchToDetectors(ctx, baseEvent)
		assert.NoError(t, err)
		require.Len(t, outputs1, 1)

		outputs2, err := engine.DispatchToDetectors(ctx, outputs1[0])
		assert.NoError(t, err)
		require.Len(t, outputs2, 1)

		finalEvent := outputs2[0]

		// Verify data is preserved in the chain
		require.NotNil(t, finalEvent.DetectedFrom)
		require.NotNil(t, finalEvent.DetectedFrom.Parent)

		// Check that original event data is in the chain
		originalData := finalEvent.DetectedFrom.Parent.Data
		require.Len(t, originalData, 2)
		assert.Equal(t, "pathname", originalData[0].Name)
		assert.Equal(t, "/bin/nc", originalData[0].GetStr())
		assert.Equal(t, "pid", originalData[1].Name)
		assert.Equal(t, int32(1234), originalData[1].GetInt32())
	})
}

// TestAutoPopulateFields_DetectedFrom_NilParent tests that nil parents don't cause issues
func TestAutoPopulateFields_DetectedFrom_NilParent(t *testing.T) {
	detector := &producingDetector{
		id:        "test_nil_parent",
		eventName: "test_nil_parent_event",
		requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "execve", Dependency: detection.DependencyRequired},
			},
		},
		autoPopulate: detection.AutoPopulateFields{
			DetectedFrom: true,
		},
	}

	_, err := CreateEventsFromDetectors(events.StartDetectorID+30300, []detection.EventDetector{detector})
	require.NoError(t, err)

	detEventID, _ := events.Core.GetDefinitionIDByName(detector.eventName)
	policyMgr := newTestPolicyManager(detEventID)

	engine := NewEngine(policyMgr, nil)
	params := detection.DetectorParams{
		Config: detection.NewEmptyDetectorConfig(),
	}

	err = engine.RegisterDetector(detector, params)
	require.NoError(t, err)
	err = engine.EnableDetector(detector.id)
	require.NoError(t, err)

	// Input event without DetectedFrom (no parent chain)
	inputEvent := &v1beta1.Event{
		Id:           v1beta1.EventId(events.Execve),
		Name:         "execve",
		DetectedFrom: nil, // No parent
	}

	ctx := context.Background()
	outputs, err := engine.DispatchToDetectors(ctx, inputEvent)
	assert.NoError(t, err)
	require.Len(t, outputs, 1)

	// Should have DetectedFrom but no parent
	output := outputs[0]
	require.NotNil(t, output.DetectedFrom)
	assert.Equal(t, uint32(events.Execve), output.DetectedFrom.Id)
	assert.Nil(t, output.DetectedFrom.Parent) // Should be nil, not cause panic
}
