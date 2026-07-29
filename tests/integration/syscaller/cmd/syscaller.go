package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

func main() {
	err := testutils.PinProccessToCPU()
	if err != nil {
		fmt.Fprintf(os.Stderr, "PinProccessToCPU: %v\n", err)
		os.Exit(1)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if len(os.Args) < 3 {
		fmt.Println("usage: syscaller caller_comm sycall_number[...]")
		os.Exit(0)
	}

	callerComm := os.Args[1]
	syscallsToCall := make([]events.ID, 0)
	for _, arg := range os.Args[2:] {
		syscallNum, err := strconv.Atoi(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid syscall number: %s\n", arg)
			os.Exit(1)
		}
		syscallsToCall = append(syscallsToCall, events.ID(syscallNum))
	}

	err = changeOwnComm(callerComm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Build arg presets over a real scratch file so file syscalls actually succeed and reach
	// the kernel hooks that emit derived/security events (falls back to zero args for the rest).
	argsMap, cleanup, keepAlive, err := setupSyscallContext()
	if err != nil {
		// Non-fatal: fall back to the default (zero-arg) map, which still fires syscall-name events.
		fmt.Fprintf(os.Stderr, "syscall context setup failed, using zero args: %v\n", err)
		argsMap = syscallMap
	}

	// do the magic
	errs := callsys(syscallsToCall, argsMap)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "errors: %v\n", errs)
	}
	runtime.KeepAlive(keepAlive) // hold the scratch buffers until every syscall has run

	cleanup() // explicit: os.Exit below skips deferred calls
	os.Exit(0)
}
