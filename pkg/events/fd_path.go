package events

// MaxFDPathSize matches MAX_FD_PATH_SIZE in the BPF program and includes the
// terminating NUL. Longer paths are reported as truncated.
const MaxFDPathSize = 256

// FDPathStatus matches fd_path_status_e in the BPF program.
type FDPathStatus uint8

const (
	FDPathNone FDPathStatus = iota
	FDPathUnavailable
	FDPathResolved
	FDPathReadError
	FDPathStorageError
	FDPathTruncated
)

// FDPath is an entry-time snapshot owned by the event, not by a kernel cache.
// The numeric argument stays intact until output formatting, so filters and
// detectors continue to see the syscall's original argument type.
type FDPath struct {
	ArgIndex uint8
	// ArgName comes from the event definition at ArgIndex, before protobuf conversion.
	ArgName string
	Status  FDPathStatus
	Path    string
}
