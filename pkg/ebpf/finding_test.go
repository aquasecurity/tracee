package ebpf

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestFindingToEvent(t *testing.T) {
	t.Parallel()

	expected := &trace.Event{
		EventID:             int(events.StartSignatureID),
		EventName:           "fake_signature_event",
		ProcessorID:         1,
		ProcessID:           2,
		CgroupID:            3,
		ThreadID:            4,
		ParentProcessID:     5,
		HostProcessID:       6,
		HostThreadID:        7,
		HostParentProcessID: 8,
		UserID:              9,
		MountNS:             10,
		PIDNS:               11,
		ProcessName:         "process",
		HostName:            "host",
		Container: trace.Container{
			ID:        "containerID",
			ImageName: "image",
			Name:      "container",
		},
		Kubernetes: trace.Kubernetes{
			PodName:      "pod",
			PodNamespace: "namespace",
			PodUID:       "uid",
		},
		ReturnValue:           10,
		MatchedPoliciesKernel: 1,
		MatchedPoliciesUser:   1,
		ArgsNum:               3,
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "arg1",
					Type: "const char *",
				},
				Value: "value1",
			},
			{
				ArgMeta: trace.ArgMeta{
					Name: "arg2",
					Type: "int",
				},
				Value: 1,
			},
			{
				ArgMeta: trace.ArgMeta{
					Name: "triggeredBy",
					Type: "unknown",
				},
				Value: map[string]interface{}{
					"id":   int(events.Ptrace),
					"name": "ptrace",
					"args": []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "arg1",
								Type: "const char *",
							},
							Value: "arg value",
						},
					},
					"returnValue": 10,
				},
			},
		},
		Metadata: &trace.Metadata{
			Version:     "1",
			Description: "description",
			Tags:        []string{"tag1", "tag2"},
			Properties: map[string]interface{}{
				"prop1":         "value1",
				"prop2":         1,
				"signatureID":   "fake_signature_id",
				"signatureName": "fake_signature_event",
				"Severity":      2,
				"Category":      "privilege-escalation",
				"Technique":     "Exploitation for Privilege Escalation",
				"id":            "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839",
				"external_id":   "t1000",
			},
		},
	}

	finding := createFakeEventAndFinding()
	got, err := FindingToEvent(&finding)

	assert.NoError(t, err)

	// sort arguments to avoid flaky tests
	sort.Slice(got.Args, func(i, j int) bool { return got.Args[i].Name < got.Args[j].Name })
	sort.Slice(expected.Args, func(i, j int) bool { return expected.Args[i].Name < expected.Args[j].Name })

	assert.Equal(t, got, expected)
}

func createFakeEventAndFinding() detect.Finding {
	eventName := "fake_signature_event"

	eventDefinition := events.NewDefinition(
		0,                          // id
		events.Sys32Undefined,      // id32
		eventName,                  // eventName
		events.NewVersion(1, 0, 0), // Version
		"fake_description",         // description
		"",                         // docPath
		false,                      // internal
		false,                      // syscall
		[]string{"signatures"},     // sets
		events.NewDependencies(
			[]events.ID{events.Ptrace},
			[]events.KSymbol{},
			[]events.Probe{},
			[]events.TailCall{},
			events.Capabilities{},
		),
		[]trace.ArgMeta{},
		nil,
	)

	events.Core.Add(events.StartSignatureID, eventDefinition)

	return detect.Finding{
		SigMetadata: detect.SignatureMetadata{
			ID:          "fake_signature_id",
			Name:        eventName,
			EventName:   eventName,
			Version:     "1",
			Description: "description",
			Tags:        []string{"tag1", "tag2"},
			Properties: map[string]interface{}{
				"prop1":       "value1",
				"prop2":       1,
				"Severity":    2,
				"Category":    "privilege-escalation",
				"Technique":   "Exploitation for Privilege Escalation",
				"id":          "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839",
				"external_id": "t1000",
			},
		},
		Data: map[string]interface{}{
			"arg1": "value1",
			"arg2": 1,
		},
		Event: protocol.Event{
			Headers: protocol.EventHeaders{},
			Payload: trace.Event{
				EventID:             int(events.Ptrace),
				EventName:           "ptrace",
				ProcessorID:         1,
				ProcessID:           2,
				CgroupID:            3,
				ThreadID:            4,
				ParentProcessID:     5,
				HostProcessID:       6,
				HostThreadID:        7,
				HostParentProcessID: 8,
				UserID:              9,
				MountNS:             10,
				PIDNS:               11,
				ProcessName:         "process",
				HostName:            "host",
				Container: trace.Container{
					ID:        "containerID",
					Name:      "container",
					ImageName: "image",
				},
				Kubernetes: trace.Kubernetes{
					PodName:      "pod",
					PodNamespace: "namespace",
					PodUID:       "uid",
				},
				ReturnValue:           10,
				MatchedPoliciesKernel: 1,
				MatchedPoliciesUser:   1,
				ArgsNum:               1,
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "arg1",
							Type: "const char *",
						},
						Value: "arg value",
					},
				},
			},
		},
	}
}
