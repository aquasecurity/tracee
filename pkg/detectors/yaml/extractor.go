package yaml

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/errfmt"
)

// FieldExtractor extracts a field from an Event and returns it as an EventValue
type FieldExtractor interface {
	Extract(event *v1beta1.Event) (*v1beta1.EventValue, error)
	Name() string
	IsOptional() bool
}

// fieldExtractor implements FieldExtractor
type fieldExtractor struct {
	name       string
	expression string
	optional   bool
	path       []string // Parsed path segments
}

// NewFieldExtractor creates a new field extractor from an extraction specification
func NewFieldExtractor(spec ExtractFieldSpec) (FieldExtractor, error) {
	if spec.Name == "" {
		return nil, errfmt.Errorf("field name cannot be empty")
	}

	if spec.Expression == "" {
		return nil, errfmt.Errorf("field expression cannot be empty")
	}

	// Parse the expression path
	path := strings.Split(spec.Expression, ".")
	if len(path) == 0 {
		return nil, errfmt.Errorf("invalid expression path '%s'", spec.Expression)
	}

	return &fieldExtractor{
		name:       spec.Name,
		expression: spec.Expression,
		optional:   spec.Optional,
		path:       path,
	}, nil
}

// Name returns the field name
func (e *fieldExtractor) Name() string {
	return e.name
}

// IsOptional returns whether the field is optional
func (e *fieldExtractor) IsOptional() bool {
	return e.optional
}

// Extract extracts the field value from an event
func (e *fieldExtractor) Extract(event *v1beta1.Event) (*v1beta1.EventValue, error) {
	if event == nil {
		return nil, errfmt.Errorf("event cannot be nil")
	}

	// Route to appropriate extractor based on root path segment
	root := e.path[0]

	switch root {
	case "data":
		return e.extractFromData(event)
	case "workload":
		return e.extractFromWorkload(event)
	case "timestamp":
		return e.extractTimestamp(event)
	case "name":
		return e.extractName(event)
	default:
		return nil, errfmt.Errorf("unsupported root path '%s' in expression '%s'", root, e.expression)
	}
}

// extractFromData extracts a field from Event.Data
func (e *fieldExtractor) extractFromData(event *v1beta1.Event) (*v1beta1.EventValue, error) {
	if len(e.path) < 2 {
		return nil, errfmt.Errorf("data path requires at least 2 segments: %s", e.expression)
	}

	fieldName := e.path[1]

	// Find the field in event data
	for _, dataValue := range event.Data {
		if dataValue.Name == fieldName {
			// Return a copy with our field name
			return &v1beta1.EventValue{
				Name:  e.name,
				Value: dataValue.Value,
			}, nil
		}
	}

	return nil, errfmt.Errorf("data field '%s' not found", fieldName)
}

// extractFromWorkload extracts a field from Event.Workload using v1beta1 helpers
func (e *fieldExtractor) extractFromWorkload(event *v1beta1.Event) (*v1beta1.EventValue, error) {
	// Use v1beta1 helpers for all workload field extractions
	switch e.expression {
	// Process fields
	case "workload.process.pid.value":
		pid := v1beta1.GetProcessPid(event)
		if pid == 0 && !e.optional {
			return nil, errfmt.Errorf("process pid is missing or zero")
		}
		return v1beta1.NewUInt32Value(e.name, pid), nil

	case "workload.process.unique_id.value", "workload.process.entity_id.value":
		entityID := v1beta1.GetProcessEntityId(event)
		if entityID == 0 && !e.optional {
			return nil, errfmt.Errorf("process unique_id is missing or zero")
		}
		return v1beta1.NewUInt32Value(e.name, entityID), nil

	case "workload.process.host_pid.value":
		hostPid := v1beta1.GetProcessHostPid(event)
		if hostPid == 0 && !e.optional {
			return nil, errfmt.Errorf("process host_pid is missing or zero")
		}
		return v1beta1.NewUInt32Value(e.name, hostPid), nil

	case "workload.process.executable.path":
		path := v1beta1.GetProcessExecutablePath(event)
		if path == "" && !e.optional {
			return nil, errfmt.Errorf("process executable path is missing")
		}
		return v1beta1.NewStringValue(e.name, path), nil

	case "workload.process.real_user.id.value":
		userId := v1beta1.GetProcessRealUserId(event)
		if userId == 0 && !e.optional {
			return nil, errfmt.Errorf("process real_user.id is missing or zero")
		}
		return v1beta1.NewUInt32Value(e.name, userId), nil

	// Thread fields
	case "workload.process.thread.name":
		name := v1beta1.GetProcessThreadName(event)
		if name == "" && !e.optional {
			return nil, errfmt.Errorf("process thread name is missing")
		}
		return v1beta1.NewStringValue(e.name, name), nil

	case "workload.process.thread.syscall":
		syscall := v1beta1.GetProcessThreadSyscall(event)
		if syscall == "" && !e.optional {
			return nil, errfmt.Errorf("process thread syscall is missing")
		}
		return v1beta1.NewStringValue(e.name, syscall), nil

	case "workload.process.thread.tid.value":
		tid := v1beta1.GetProcessThreadTid(event)
		if tid == 0 && !e.optional {
			return nil, errfmt.Errorf("thread tid is missing or zero")
		}
		return v1beta1.NewUInt32Value(e.name, tid), nil

	case "workload.process.thread.host_tid.value":
		hostTid := v1beta1.GetProcessThreadHostTid(event)
		if hostTid == 0 && !e.optional {
			return nil, errfmt.Errorf("thread host_tid is missing or zero")
		}
		return v1beta1.NewUInt32Value(e.name, hostTid), nil

	case "workload.process.thread.unique_id.value":
		entityId := v1beta1.GetProcessThreadEntityId(event)
		if entityId == 0 && !e.optional {
			return nil, errfmt.Errorf("thread unique_id is missing or zero")
		}
		return v1beta1.NewUInt32Value(e.name, entityId), nil

	// Container fields
	case "workload.container.id":
		id := v1beta1.GetContainerID(event)
		if id == "" && !e.optional {
			return nil, errfmt.Errorf("container id is missing")
		}
		return v1beta1.NewStringValue(e.name, id), nil

	case "workload.container.name":
		name := v1beta1.GetContainerName(event)
		if name == "" && !e.optional {
			return nil, errfmt.Errorf("container name is missing")
		}
		return v1beta1.NewStringValue(e.name, name), nil

	case "workload.container.started":
		started := v1beta1.GetContainerStarted(event)
		return v1beta1.NewBoolValue(e.name, started), nil

	case "workload.container.image.id":
		imageId := v1beta1.GetContainerImageId(event)
		if imageId == "" && !e.optional {
			return nil, errfmt.Errorf("container image id is missing")
		}
		return v1beta1.NewStringValue(e.name, imageId), nil

	case "workload.container.image.name":
		imageName := v1beta1.GetContainerImageName(event)
		if imageName == "" && !e.optional {
			return nil, errfmt.Errorf("container image name is missing")
		}
		return v1beta1.NewStringValue(e.name, imageName), nil

	// K8s fields
	case "workload.k8s.pod.name":
		podName := v1beta1.GetK8sPodName(event)
		if podName == "" && !e.optional {
			return nil, errfmt.Errorf("k8s pod name is missing")
		}
		return v1beta1.NewStringValue(e.name, podName), nil

	case "workload.k8s.pod.uid":
		podUid := v1beta1.GetK8sPodUid(event)
		if podUid == "" && !e.optional {
			return nil, errfmt.Errorf("k8s pod uid is missing")
		}
		return v1beta1.NewStringValue(e.name, podUid), nil

	case "workload.k8s.namespace.name":
		nsName := v1beta1.GetK8sNamespaceName(event)
		if nsName == "" && !e.optional {
			return nil, errfmt.Errorf("k8s namespace name is missing")
		}
		return v1beta1.NewStringValue(e.name, nsName), nil

	default:
		return nil, errfmt.Errorf("unsupported workload path '%s'", e.expression)
	}
}

// extractTimestamp extracts the event timestamp
func (e *fieldExtractor) extractTimestamp(event *v1beta1.Event) (*v1beta1.EventValue, error) {
	if event.Timestamp == nil {
		return nil, errfmt.Errorf("timestamp is nil")
	}

	// Return timestamp as uint64 (nanoseconds since epoch)
	nanos := uint64(event.Timestamp.Seconds)*1e9 + uint64(event.Timestamp.Nanos)
	return v1beta1.NewUInt64Value(e.name, nanos), nil
}

// extractName extracts the event name
func (e *fieldExtractor) extractName(event *v1beta1.Event) (*v1beta1.EventValue, error) {
	return v1beta1.NewStringValue(e.name, event.Name), nil
}

// BuildExtractors creates extractors from output specification
func BuildExtractors(spec *OutputSpec) ([]FieldExtractor, error) {
	if spec == nil || len(spec.Fields) == 0 {
		return nil, nil
	}

	extractors := make([]FieldExtractor, 0, len(spec.Fields))

	for _, fieldSpec := range spec.Fields {
		extractor, err := NewFieldExtractor(fieldSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to create extractor for field '%s': %w", fieldSpec.Name, err)
		}
		extractors = append(extractors, extractor)
	}

	return extractors, nil
}
