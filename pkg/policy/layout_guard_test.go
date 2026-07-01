package policy

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// Test_GoCLayoutContract guards the byte layout of the Go structs that are written verbatim into
// BPF maps (via unsafe.Pointer) and therefore MUST stay byte-compatible with their C counterparts.
// A size/offset drift here (an added or reordered field) would otherwise become a silent runtime
// mismatch, exactly the class of bug behind the filter_version_key padding regression.
func Test_GoCLayoutContract(t *testing.T) {
	t.Parallel()

	// C filter_version_key_t { u16 version; u32 event_id; } -> 8 bytes with 2 bytes of implicit
	// padding after version; event_id lands at offset 4. The Go struct's explicit Pad field keeps
	// the inserted key's padding bytes zeroed so kernel HASH_OF_MAPS lookups match.
	require.Equal(t, uintptr(8), unsafe.Sizeof(filterVersionKey{}), "filterVersionKey size")
	require.Equal(t, uintptr(0), unsafe.Offsetof(filterVersionKey{}.Version), "Version offset")
	require.Equal(t, uintptr(4), unsafe.Offsetof(filterVersionKey{}.EventID), "EventID offset")

	// C event_config_t: the value type of events_config_map (bpftool reports value 288B).
	require.Equal(t, uintptr(288), unsafe.Sizeof(eventConfig{}), "eventConfig size")
}
