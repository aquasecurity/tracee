package v1beta1

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// EventDataType constraint for type-safe data extraction from Event.Data
type EventDataType interface {
	string | int32 | int64 | uint32 | uint64 | []byte | bool
}

// GetData extracts a value from Event.Data by name with type safety.
// Returns the value and true if found, or zero value and false if not found.
// Use for optional fields where missing data is acceptable.
func GetData[T EventDataType](event *Event, name string) (T, bool) {
	var zero T
	if event == nil || event.Data == nil {
		return zero, false
	}

	for _, arg := range event.Data {
		if arg.Name == name {
			return extractValue[T](arg)
		}
	}

	return zero, false
}

// GetDataSafe extracts a value from Event.Data by name with error reporting.
// Returns the value if found, or an error if the field is missing or has wrong type.
// Use for required fields where missing data is an error.
func GetDataSafe[T EventDataType](event *Event, name string) (T, error) {
	var zero T
	if event == nil {
		return zero, errors.New("event is nil")
	}
	if event.Data == nil {
		return zero, errors.New("event.Data is nil")
	}

	for _, arg := range event.Data {
		if arg.Name == name {
			val, found := extractValue[T](arg)
			if !found {
				return zero, fmt.Errorf("field %q has incompatible type for %T", name, zero)
			}
			return val, nil
		}
	}

	return zero, fmt.Errorf("field %q not found in event data", name)
}

// extractValue extracts typed value from EventValue oneof wrapper
func extractValue[T EventDataType](ev *EventValue) (T, bool) {
	var zero T

	if ev == nil || ev.Value == nil {
		return zero, false
	}

	// Type switch on the constraint to handle each case
	switch any(zero).(type) {
	case string:
		if v, ok := ev.Value.(*EventValue_Str); ok {
			if result, ok := any(v.Str).(T); ok {
				return result, true
			}
		}
	case int32:
		if v, ok := ev.Value.(*EventValue_Int32); ok {
			if result, ok := any(v.Int32).(T); ok {
				return result, true
			}
		}
	case int64:
		if v, ok := ev.Value.(*EventValue_Int64); ok {
			if result, ok := any(v.Int64).(T); ok {
				return result, true
			}
		}
	case uint32:
		if v, ok := ev.Value.(*EventValue_UInt32); ok {
			if result, ok := any(v.UInt32).(T); ok {
				return result, true
			}
		}
	case uint64:
		if v, ok := ev.Value.(*EventValue_UInt64); ok {
			if result, ok := any(v.UInt64).(T); ok {
				return result, true
			}
		}
	case []byte:
		if v, ok := ev.Value.(*EventValue_Bytes); ok {
			if result, ok := any(v.Bytes).(T); ok {
				return result, true
			}
		}
	case bool:
		if v, ok := ev.Value.(*EventValue_Bool); ok {
			if result, ok := any(v.Bool).(T); ok {
				return result, true
			}
		}
	}

	return zero, false
}

// GetProcessPid returns the process PID from the event, or 0 if not available.
// Null-safe: handles nil Workload or Process.
func GetProcessPid(event *Event) uint32 {
	if event == nil || event.Workload == nil || event.Workload.Process == nil {
		return 0
	}
	if event.Workload.Process.Pid != nil {
		return event.Workload.Process.Pid.Value
	}
	return 0
}

// GetProcessEntityId returns the process entity ID from the event, or 0 if not available.
// Null-safe: handles nil Workload or Process.
func GetProcessEntityId(event *Event) uint32 {
	if event == nil || event.Workload == nil || event.Workload.Process == nil {
		return 0
	}
	if event.Workload.Process.UniqueId != nil {
		return event.Workload.Process.UniqueId.Value
	}
	return 0
}

// GetProcessExecutablePath returns the executable path from the event, or empty string if not available.
// Null-safe: handles nil Workload, Process, or Executable.
func GetProcessExecutablePath(event *Event) string {
	if event == nil || event.Workload == nil || event.Workload.Process == nil {
		return ""
	}
	if event.Workload.Process.Executable != nil {
		return event.Workload.Process.Executable.Path
	}
	return ""
}

// GetContainerID returns the container ID from the event, or empty string if not available.
// Null-safe: handles nil Workload or Container.
func GetContainerID(event *Event) string {
	if event == nil || event.Workload == nil || event.Workload.Container == nil {
		return ""
	}
	return event.Workload.Container.Id
}

// GetContainerName returns the container name from the event, or empty string if not available.
// Null-safe: handles nil Workload or Container.
func GetContainerName(event *Event) string {
	if event == nil || event.Workload == nil || event.Workload.Container == nil {
		return ""
	}
	return event.Workload.Container.Name
}

// GetContainerImageName returns the container image name from the event, or empty string if not available.
// Null-safe: handles nil Workload, Container, or Image.
func GetContainerImageName(event *Event) string {
	if event == nil || event.Workload == nil || event.Workload.Container == nil {
		return ""
	}
	if event.Workload.Container.Image != nil {
		return event.Workload.Container.Image.Name
	}
	return ""
}

// CreateEventFromBase creates a new event derived from baseEvent.
// This is the universal event creation helper for all detector types.
//
// COPIED FIELDS: Timestamp, Workload (deep cloned), Policies (deep cloned)
// CLEARED FIELDS: Id, Name, Data, Threat, DetectedFrom (set to zero values)
//
// ENGINE RESPONSIBILITIES:
//   - Assigns Id and Name during post-processing based on detector's produced event
//   - Auto-populates Threat, DetectedFrom, ProcessAncestry if declared in AutoPopulateFields
//
// DETECTOR RESPONSIBILITIES:
//   - Populate Data field with detection/derivation results (runtime-specific information)
//
// USAGE:
//   - Call this to create output events in detector OnEvent() implementations
//   - Set Data field with your detection results
//   - Engine handles metadata population based on detector definition
func CreateEventFromBase(baseEvent *Event) *Event {
	if baseEvent == nil {
		return &Event{}
	}

	newEvent := &Event{
		Timestamp: baseEvent.Timestamp,
		// Id and Name left as zero - engine assigns these during post-processing
	}

	// Deep clone Workload to prevent modifications affecting base event
	if baseEvent.Workload != nil {
		if cloned, ok := proto.Clone(baseEvent.Workload).(*Workload); ok {
			newEvent.Workload = cloned
		}
	}

	// Deep clone Policies to prevent modifications affecting base event
	if baseEvent.Policies != nil {
		if cloned, ok := proto.Clone(baseEvent.Policies).(*Policies); ok {
			newEvent.Policies = cloned
		}
	}

	// Data left as nil - detector populates with detection results
	// Threat, DetectedFrom left as nil - engine populates based on AutoPopulateFields

	return newEvent
}
