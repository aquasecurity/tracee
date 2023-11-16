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

	eventDefID, found := events.Core.GetDefinitionIDByName(f.SigMetadata.EventName)
	if !found {
		return nil, errfmt.Errorf("error finding event not found: %s", f.SigMetadata.EventName)
	}

	return newEvent(int(eventDefID), f, s), nil
}

func newEvent(id int, f detect.Finding, e trace.Event) *trace.Event {
	arguments := getArguments(f, e)
	metadata := getMetadataFromSignatureMetadata(f.SigMetadata)

	return &trace.Event{
		EventID:               id,
		EventName:             f.SigMetadata.EventName,
		Timestamp:             e.Timestamp,
		ThreadStartTime:       e.ThreadStartTime,
		ProcessorID:           e.ProcessorID,
		ProcessID:             e.ProcessID,
		CgroupID:              e.CgroupID,
		ThreadID:              e.ThreadID,
		ParentProcessID:       e.ParentProcessID,
		HostProcessID:         e.HostProcessID,
		HostThreadID:          e.HostThreadID,
		HostParentProcessID:   e.HostParentProcessID,
		UserID:                e.UserID,
		MountNS:               e.MountNS,
		PIDNS:                 e.PIDNS,
		ProcessName:           e.ProcessName,
		Executable:            e.Executable,
		HostName:              e.HostName,
		ContainerID:           e.ContainerID,
		Container:             e.Container,
		Kubernetes:            e.Kubernetes,
		ReturnValue:           e.ReturnValue,
		Syscall:               e.Syscall,
		StackAddresses:        e.StackAddresses,
		ContextFlags:          e.ContextFlags,
		ThreadEntityId:        e.ThreadEntityId,
		ProcessEntityId:       e.ProcessEntityId,
		ParentEntityId:        e.ParentEntityId,
		MatchedPoliciesKernel: e.MatchedPoliciesKernel,
		MatchedPoliciesUser:   e.MatchedPoliciesUser,
		ArgsNum:               len(arguments),
		Args:                  arguments,
		Metadata:              metadata,
	}
}

func getArguments(f detect.Finding, triggerEvent trace.Event) []trace.Argument {
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

	if len(triggerEvent.Args) > 0 {
		arg := trace.Argument{
			ArgMeta: trace.ArgMeta{
				Name: "triggeredBy",
				Type: "unknown",
			},
			Value: map[string]interface{}{
				"id":          triggerEvent.EventID,
				"name":        triggerEvent.EventName,
				"args":        triggerEvent.Args,
				"returnValue": triggerEvent.ReturnValue,
			},
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

	// This is temporary, we passing all the signatures metadata,
	// so we can create the Threat in the protobuf for the grpc API,
	// once we refactor tracee to use the new event structure,
	// we will create the Threat here, or maybe return it from the rule engine
	metadata.Properties["Severity"] = sigMetadata.Properties["Severity"]
	metadata.Properties["Category"] = sigMetadata.Properties["Category"]
	metadata.Properties["Technique"] = sigMetadata.Properties["Technique"]
	metadata.Properties["id"] = sigMetadata.Properties["id"]
	metadata.Properties["external_id"] = sigMetadata.Properties["external_id"]

	return metadata
}
