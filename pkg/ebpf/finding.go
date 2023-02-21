package ebpf

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

// FindingToEvent converts a detect.Finding into a trace.Event
// This is used because the pipeline expects trace.Event, but the rule engine returns detect.Finding
func FindingToEvent(f detect.Finding) (*trace.Event, error) {
	s, ok := f.Event.Payload.(trace.Event)

	if !ok {
		return nil, fmt.Errorf("error converting finding to event: %s", f.SigMetadata.ID)
	}

	eventID, found := events.Definitions.GetID(f.SigMetadata.EventName)
	if !found {
		return nil, fmt.Errorf("error finding event not found: %s", f.SigMetadata.EventName)
	}

	return newEvent(int(eventID), f.SigMetadata, s), nil
}

func newEvent(id int, sigMetadata detect.SignatureMetadata, s trace.Event) *trace.Event {
	metadata := getMetadataFromSignatureMetadata(sigMetadata)

	return &trace.Event{
		EventID:             id,
		EventName:           sigMetadata.Name,
		Timestamp:           s.Timestamp,
		ThreadStartTime:     s.ThreadStartTime,
		ProcessorID:         s.ProcessorID,
		ProcessID:           s.ProcessID,
		CgroupID:            s.CgroupID,
		ThreadID:            s.ThreadID,
		ParentProcessID:     s.ParentProcessID,
		HostProcessID:       s.HostProcessID,
		HostThreadID:        s.HostThreadID,
		HostParentProcessID: s.HostParentProcessID,
		UserID:              s.UserID,
		MountNS:             s.MountNS,
		PIDNS:               s.PIDNS,
		ProcessName:         s.ProcessName,
		HostName:            s.HostName,
		ContainerID:         s.ContainerID,
		ContainerImage:      s.ContainerImage,
		ContainerName:       s.ContainerName,
		PodName:             s.PodName,
		PodNamespace:        s.PodNamespace,
		PodUID:              s.PodUID,
		ArgsNum:             s.ArgsNum,
		ReturnValue:         s.ReturnValue,
		StackAddresses:      s.StackAddresses,
		ContextFlags:        s.ContextFlags,
		MatchedScopes:       s.MatchedScopes,
		Args:                s.Args,
		Metadata:            metadata,
	}
}

func getMetadataFromSignatureMetadata(sigMetadata detect.SignatureMetadata) *trace.Metadata {
	metadata := &trace.Metadata{}

	metadata.Version = sigMetadata.Version
	metadata.Description = sigMetadata.Description
	metadata.Tags = sigMetadata.Tags

	properties := sigMetadata.Properties
	if sigMetadata.Properties == nil {
		properties = make(map[string]interface{})
	}

	metadata.Properties = properties
	metadata.Properties["signatureID"] = sigMetadata.ID
	metadata.Properties["signatureName"] = sigMetadata.Name

	return metadata
}
