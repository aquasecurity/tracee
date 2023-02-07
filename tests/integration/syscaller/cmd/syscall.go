package main

import (
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

// syscallMap is a map of syscall numbers to the arguments they should be
// called with. If the syscall number is not found in the map, the syscall
// is called with arguments set to 0
// Some events.ID are internal to tracee and are not syscall numbers, so they
// need further processing before being passed to the syscall
var syscallMap = map[events.ID]sysArgs{
	events.Read: {0, 0, 0, 0, 0, 0},
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

// callsys calls the given events.IDs as syscalls
func callsys(syscalls []events.ID) []error {
	errs := make([]error, 0)
	for _, sysNum := range syscalls {
		var errno syscall.Errno

		if s, found := syscallMap[sysNum]; found {
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
