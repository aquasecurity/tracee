package v1beta1

import (
	"errors"
	"fmt"
)

// EventDataType constraint for type-safe data extraction from Event.Data
type EventDataType interface {
	string | int32 | int64 | uint32 | uint64 | []byte | bool
}

// GetData extracts a value from Event.Data by name with type safety.
// Returns the value and true if found and type-compatible,
// or zero value and false if not found or type mismatch.
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
func GetProcessPid(event *Event) uint32 {
	return event.GetWorkload().GetProcess().GetPid().GetValue()
}

// GetProcessEntityId returns the process entity ID from the event, or 0 if not available.
func GetProcessEntityId(event *Event) uint32 {
	return event.GetWorkload().GetProcess().GetUniqueId().GetValue()
}

// GetProcessExecutablePath returns the executable path from the event, or empty string if not available.
func GetProcessExecutablePath(event *Event) string {
	return event.GetWorkload().GetProcess().GetExecutable().GetPath()
}

// GetContainerID returns the container ID from the event, or empty string if not available.
func GetContainerID(event *Event) string {
	return event.GetWorkload().GetContainer().GetId()
}

// GetContainerName returns the container name from the event, or empty string if not available.
func GetContainerName(event *Event) string {
	return event.GetWorkload().GetContainer().GetName()
}

// GetContainerImageName returns the container image name from the event, or empty string if not available.
func GetContainerImageName(event *Event) string {
	return event.GetWorkload().GetContainer().GetImage().GetName()
}

// GetProcessHostPid returns the process host PID from the event, or 0 if not available.
func GetProcessHostPid(event *Event) uint32 {
	return event.GetWorkload().GetProcess().GetHostPid().GetValue()
}

// GetProcessRealUserId returns the process real user ID from the event, or 0 if not available.
func GetProcessRealUserId(event *Event) uint32 {
	return event.GetWorkload().GetProcess().GetRealUser().GetId().GetValue()
}

// GetProcessThreadName returns the thread name from the event, or empty string if not available.
func GetProcessThreadName(event *Event) string {
	return event.GetWorkload().GetProcess().GetThread().GetName()
}

// GetProcessThreadSyscall returns the thread syscall from the event, or empty string if not available.
func GetProcessThreadSyscall(event *Event) string {
	return event.GetWorkload().GetProcess().GetThread().GetSyscall()
}

// GetProcessThreadTid returns the thread TID from the event, or 0 if not available.
func GetProcessThreadTid(event *Event) uint32 {
	return event.GetWorkload().GetProcess().GetThread().GetTid().GetValue()
}

// GetProcessThreadHostTid returns the thread host TID from the event, or 0 if not available.
func GetProcessThreadHostTid(event *Event) uint32 {
	return event.GetWorkload().GetProcess().GetThread().GetHostTid().GetValue()
}

// GetProcessThreadEntityId returns the thread entity ID from the event, or 0 if not available.
func GetProcessThreadEntityId(event *Event) uint32 {
	return event.GetWorkload().GetProcess().GetThread().GetUniqueId().GetValue()
}

// GetContainerStarted returns whether the container is started from the event, or false if not available.
func GetContainerStarted(event *Event) bool {
	return event.GetWorkload().GetContainer().GetStarted()
}

// GetContainerImageId returns the container image ID from the event, or empty string if not available.
func GetContainerImageId(event *Event) string {
	return event.GetWorkload().GetContainer().GetImage().GetId()
}

// GetK8sPodName returns the Kubernetes pod name from the event, or empty string if not available.
func GetK8sPodName(event *Event) string {
	return event.GetWorkload().GetK8S().GetPod().GetName()
}

// GetK8sPodUid returns the Kubernetes pod UID from the event, or empty string if not available.
func GetK8sPodUid(event *Event) string {
	return event.GetWorkload().GetK8S().GetPod().GetUid()
}

// GetK8sNamespaceName returns the Kubernetes namespace name from the event, or empty string if not available.
func GetK8sNamespaceName(event *Event) string {
	return event.GetWorkload().GetK8S().GetNamespace().GetName()
}

// EventValue constructors for common types
// These helpers simplify creating EventValue instances for detector output data.
// For basic types (string, int32, etc.), use these specific helpers for best clarity.
// For specialized types (TCP, DNS, etc.), use NewValue() with runtime type checking.

// NewStringValue creates an EventValue for a string field
func NewStringValue(name, value string) *EventValue {
	return &EventValue{
		Name:  name,
		Value: &EventValue_Str{Str: value},
	}
}

// NewInt32Value creates an EventValue for an int32 field
func NewInt32Value(name string, value int32) *EventValue {
	return &EventValue{
		Name:  name,
		Value: &EventValue_Int32{Int32: value},
	}
}

// NewInt64Value creates an EventValue for an int64 field
func NewInt64Value(name string, value int64) *EventValue {
	return &EventValue{
		Name:  name,
		Value: &EventValue_Int64{Int64: value},
	}
}

// NewUInt32Value creates an EventValue for a uint32 field
func NewUInt32Value(name string, value uint32) *EventValue {
	return &EventValue{
		Name:  name,
		Value: &EventValue_UInt32{UInt32: value},
	}
}

// NewUInt64Value creates an EventValue for a uint64 field
func NewUInt64Value(name string, value uint64) *EventValue {
	return &EventValue{
		Name:  name,
		Value: &EventValue_UInt64{UInt64: value},
	}
}

// NewBoolValue creates an EventValue for a boolean field
func NewBoolValue(name string, value bool) *EventValue {
	return &EventValue{
		Name:  name,
		Value: &EventValue_Bool{Bool: value},
	}
}

// NewBytesValue creates an EventValue for a bytes field
func NewBytesValue(name string, value []byte) *EventValue {
	return &EventValue{
		Name:  name,
		Value: &EventValue_Bytes{Bytes: value},
	}
}

// NewValue creates an EventValue for any supported type using runtime type checking.
// This is a generic fallback for specialized types (arrays, network types, credentials, etc.).
// For common basic types (string, int32, etc.), prefer the specific helpers above for better clarity.
//
// Supported types include: StringArray, Int32Array, UInt64Array, SockAddr, Credentials,
// Timespec, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, PacketMetadata, HTTP, and more.
//
// Returns error if the value type is not supported by EventValue.
func NewValue(name string, value any) (*EventValue, error) {
	ev := &EventValue{Name: name}

	switch v := value.(type) {
	// Basic types (also covered by specific helpers, but supported here for completeness)
	case string:
		ev.Value = &EventValue_Str{Str: v}
	case int32:
		ev.Value = &EventValue_Int32{Int32: v}
	case int64:
		ev.Value = &EventValue_Int64{Int64: v}
	case uint32:
		ev.Value = &EventValue_UInt32{UInt32: v}
	case uint64:
		ev.Value = &EventValue_UInt64{UInt64: v}
	case bool:
		ev.Value = &EventValue_Bool{Bool: v}
	case []byte:
		ev.Value = &EventValue_Bytes{Bytes: v}

	// Array types
	case *StringArray:
		ev.Value = &EventValue_StrArray{StrArray: v}
	case *Int32Array:
		ev.Value = &EventValue_Int32Array{Int32Array: v}
	case *UInt64Array:
		ev.Value = &EventValue_UInt64Array{UInt64Array: v}

	// Network and protocol types
	case *SockAddr:
		ev.Value = &EventValue_Sockaddr{Sockaddr: v}
	case *IPv4:
		ev.Value = &EventValue_Ipv4{Ipv4: v}
	case *IPv6:
		ev.Value = &EventValue_Ipv6{Ipv6: v}
	case *TCP:
		ev.Value = &EventValue_Tcp{Tcp: v}
	case *UDP:
		ev.Value = &EventValue_Udp{Udp: v}
	case *ICMP:
		ev.Value = &EventValue_Icmp{Icmp: v}
	case *ICMPv6:
		ev.Value = &EventValue_Icmpv6{Icmpv6: v}
	case *DNS:
		ev.Value = &EventValue_Dns{Dns: v}
	case *DnsQuestions:
		ev.Value = &EventValue_DnsQuestions{DnsQuestions: v}
	case *DnsResponses:
		ev.Value = &EventValue_DnsResponses{DnsResponses: v}
	case *PacketMetadata:
		ev.Value = &EventValue_PacketMetadata{PacketMetadata: v}

	// HTTP types
	case *HTTP:
		ev.Value = &EventValue_Http{Http: v}
	case *HTTPRequest:
		ev.Value = &EventValue_HttpRequest{HttpRequest: v}
	case *HTTPResponse:
		ev.Value = &EventValue_HttpResponse{HttpResponse: v}

	// Other specialized types
	case *Credentials:
		ev.Value = &EventValue_Credentials{Credentials: v}
	case *Timespec:
		ev.Value = &EventValue_Timespec{Timespec: v}
	case *HookedSyscalls:
		ev.Value = &EventValue_HookedSyscalls{HookedSyscalls: v}
	case *HookedSeqOps:
		ev.Value = &EventValue_HookedSeqOps{HookedSeqOps: v}

	default:
		return nil, fmt.Errorf("unsupported type %T for EventValue", value)
	}

	return ev, nil
}

// GetDetectionChain returns the full detection chain from leaf to root.
// Index 0 is the immediate parent, index N is the root/original event.
// Returns nil if the event has no DetectedFrom chain.
func GetDetectionChain(event *Event) []*DetectedFrom {
	current := event.GetDetectedFrom()
	if current == nil {
		return nil
	}

	var chain []*DetectedFrom
	for current != nil {
		chain = append(chain, current)
		current = current.Parent
	}
	return chain
}

// GetRootDetection returns the original event that started the detection chain.
// Returns nil if there is no DetectedFrom chain.
func GetRootDetection(event *Event) *DetectedFrom {
	current := event.GetDetectedFrom()
	if current == nil {
		return nil
	}

	for current.Parent != nil {
		current = current.Parent
	}
	return current
}

// GetChainDepth returns the depth of the detection chain.
// Returns 0 if there is no chain, 1 for direct detection, 2+ for chained detections.
func GetChainDepth(event *Event) int {
	return len(GetDetectionChain(event))
}
