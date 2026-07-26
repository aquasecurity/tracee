package main

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/events"
)

// sysArgs is a struct containing the arguments to be passed to a syscall
type sysArgs struct {
	arg1 uintptr
	arg2 uintptr
	arg3 uintptr
	arg4 uintptr
	arg5 uintptr
	arg6 uintptr
}

// syscallMap is the DEFAULT arg map: syscalls not present here are called with all-zero
// arguments. Zero args are enough to fire the raw-syscall (sys_enter/sys_exit) tracepoints - so
// syscall-NAME events (read/write/openat/...) emit regardless of success - but NOT the events that
// require the syscall to progress past parameter validation into a kernel hook (security_file_open,
// magic_write, other LSM/kprobe-derived events). For those, main() builds an enriched map via
// setupSyscallContext that points the file syscalls at a real scratch file. The unit test uses this
// default map to keep its zero-arg errno expectations.
var syscallMap = map[events.ID]sysArgs{
	events.Read: {0, 0, 0, 0, 0, 0},
}

// syscallCtx holds the scratch resources referenced by the enriched arg presets. The caller MUST
// keep it alive until after callsys returns: the presets store raw uintptr pointers into these
// buffers, so they must not be GC'd mid-call.
type syscallCtx struct {
	dir      string
	pathPtr  *byte   // NUL-terminated scratch file path
	rwFD     uintptr // scratch file opened O_RDWR
	readBuf  []byte
	writeBuf []byte
}

const atFDCWD = ^uintptr(99) // AT_FDCWD == -100

// setupSyscallContext creates a scratch file and returns per-syscall arg presets that make the
// file-oriented syscalls actually SUCCEED, so they reach the kernel hook points that emit derived/
// security events. It falls back to the default (zero-arg) behavior for anything it does not know.
// The returned cleanup removes the scratch dir; the returned *syscallCtx must be retained until
// callsys finishes (keep-alive for the pointers in the arg map).
func setupSyscallContext() (map[events.ID]sysArgs, func(), *syscallCtx, error) {
	dir, err := os.MkdirTemp("", "syscaller")
	if err != nil {
		return nil, func() {}, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	path := filepath.Join(dir, "scratch")
	if err := os.WriteFile(path, []byte("syscaller-scratch\n"), 0o644); err != nil {
		cleanup()
		return nil, func() {}, nil, err
	}
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		cleanup()
		return nil, func() {}, nil, err
	}
	rwFD, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		cleanup()
		return nil, func() {}, nil, err
	}

	ctx := &syscallCtx{
		dir:      dir,
		pathPtr:  pathPtr,
		rwFD:     uintptr(rwFD),
		readBuf:  make([]byte, 64),
		writeBuf: []byte("syscaller-write\n"),
	}
	pathArg := uintptr(unsafe.Pointer(ctx.pathPtr))

	// Start from the default map so unknown syscalls keep the zero-arg fallback, then override
	// the file syscalls with valid arguments. Each of these now completes successfully, driving
	// the events that only fire on a real operation (e.g. openat/open -> security_file_open).
	m := make(map[events.ID]sysArgs, len(syscallMap)+8)
	for k, v := range syscallMap {
		m[k] = v
	}
	m[events.Openat] = sysArgs{atFDCWD, pathArg, uintptr(syscall.O_RDONLY), 0, 0, 0}
	m[events.Open] = sysArgs{pathArg, uintptr(syscall.O_RDONLY), 0, 0, 0, 0}
	m[events.Read] = sysArgs{ctx.rwFD, uintptr(unsafe.Pointer(&ctx.readBuf[0])), uintptr(len(ctx.readBuf)), 0, 0, 0}
	m[events.Write] = sysArgs{ctx.rwFD, uintptr(unsafe.Pointer(&ctx.writeBuf[0])), uintptr(len(ctx.writeBuf)), 0, 0, 0}
	m[events.Newfstatat] = sysArgs{atFDCWD, pathArg, uintptr(unsafe.Pointer(&ctx.readBuf[0])), 0, 0, 0}

	return m, cleanup, ctx, nil
}

// changeOwnComm changes the comm of the current process to the given string
func changeOwnComm(newComm string) error {
	comm, err := syscall.BytePtrFromString(newComm)
	if err != nil {
		return err
	}

	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_NAME, uintptr(unsafe.Pointer(comm)), 0)
	if errno != 0 {
		return syscall.Errno(errno)
	}

	return nil
}

// callsys calls the given events.IDs as syscalls, using argsMap for per-syscall arguments (any
// syscall absent from argsMap is called with all-zero arguments).
func callsys(syscalls []events.ID, argsMap map[events.ID]sysArgs) []error {
	errs := make([]error, 0)
	for _, sysNum := range syscalls {
		var errno syscall.Errno

		if s, found := argsMap[sysNum]; found {
			_, _, errno = syscall.RawSyscall6(uintptr(sysNum), s.arg1, s.arg2, s.arg3, s.arg4, s.arg5, s.arg6)
		} else {
			_, _, errno = syscall.RawSyscall6(uintptr(sysNum), 0, 0, 0, 0, 0, 0)
		}
		if errno != 0 {
			errs = append(errs, syscall.Errno(errno))
		}
	}

	return errs
}
