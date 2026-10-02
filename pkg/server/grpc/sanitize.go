package grpc

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// Helpers that make detector catalog properties safe to put in a protobuf
// message: strings are coerced to valid UTF-8 with
// events.SanitizeStringForProtobuf and values are converted to the Go types
// structpb accepts.

// sanitizeMapForProtobuf recursively sanitizes string values in a map
// to ensure they contain only valid UTF-8 characters
func sanitizeMapForProtobuf(m map[string]interface{}) map[string]interface{} {
	sanitizedMap := make(map[string]interface{}, len(m))

	for k, v := range m {
		sanitizedMap[k] = sanitizeValueForProtobuf(v)
	}

	return sanitizedMap
}

// sanitizeValueForProtobuf converts a value to a protobuf-compatible format
func sanitizeValueForProtobuf(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return events.SanitizeStringForProtobuf(val)
	case map[string]interface{}:
		return sanitizeMapForProtobuf(val)
	case []trace.Argument:
		args := make([]interface{}, 0, len(val))
		for _, arg := range val {
			argMap := map[string]interface{}{
				"name":  events.SanitizeStringForProtobuf(arg.ArgMeta.Name),
				"type":  events.SanitizeStringForProtobuf(arg.ArgMeta.Type),
				"value": sanitizeValueForProtobuf(arg.Value),
			}
			args = append(args, argMap)
		}
		return args
	case trace.Pointer:
		return uint64(val)
	case []string:
		result := make([]interface{}, len(val))
		for i, s := range val {
			result[i] = events.SanitizeStringForProtobuf(s)
		}
		return result
	case []uint64:
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = v
		}
		return result
	case [2]int32:
		return []interface{}{val[0], val[1]}
	case map[string]string:
		m := make(map[string]interface{}, len(val))
		for k, v := range val {
			m[k] = events.SanitizeStringForProtobuf(v)
		}
		return m
	default:
		return val
	}
}
