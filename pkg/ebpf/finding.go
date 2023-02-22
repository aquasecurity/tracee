package ebpf

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

// FindingToEvent converts a detect.Finding into a trace.Event
// This is used because the pipeline expects trace.Event, but the rule engine returns detect.Finding
func FindingToEvent(f detect.Finding) (*trace.Event, error) {
	s, ok := f.Event.Payload.(trace.Event)

	if !ok {
		return nil, errfmt.Errorf("error converting finding to event: %s", f.SigMetadata.ID)
	}

	eventID, found := events.Definitions.GetID(f.SigMetadata.EventName)
	if !found {
		return nil, errfmt.Errorf("error finding event not found: %s", f.SigMetadata.EventName)
	}

	return newEvent(int(eventID), f, s), nil
}

func newEvent(id int, f detect.Finding, s trace.Event) *trace.Event {
	arguments := getArguments(f)
	metadata := getMetadataFromSignatureMetadata(f.SigMetadata)

	return &trace.Event{
		EventID:             id,
		EventName:           f.SigMetadata.EventName,
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
		Container:           s.Container,
		Kubernetes:          s.Kubernetes,
		ReturnValue:         s.ReturnValue,
		StackAddresses:      s.StackAddresses,
		ContextFlags:        s.ContextFlags,
		MatchedPolicies:     s.MatchedPolicies,
		ArgsNum:             len(arguments),
		Args:                arguments,
		Metadata:            metadata,
	}
}

func getArguments(f detect.Finding) []trace.Argument {
	arguments := make([]trace.Argument, 0, len(f.Data))

	for k, v := range f.Data {
		arg := trace.Argument{
			ArgMeta: trace.ArgMeta{
				Name: k,
				Type: getCType(v),
			},
			Value: v,
		}

		arguments = append(arguments, arg)
	}

	return arguments
}

// TODO: we probably should have internal types instead of using kernel, or golang types
func getCType(t interface{}) string {
	switch t.(type) {
	case int16:
		return "short"
	case int32:
		return "int"
	case int:
		return "int"
	case int64:
		return "long long"
	case uint16:
		return "unsigned short"
	case uint32:
		return "unsigned int"
	case uint64:
		return "unsigned long long"
	case string:
		return "const char *"
	case bool:
		return "bool"
	case float32:
		return "float"
	case float64:
		return "long double"
	default: // TODO: how to implement int8, uint8, pointers, slices, and maps
		return "unknown"
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
