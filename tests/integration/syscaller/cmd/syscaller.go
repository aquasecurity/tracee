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

	// do the magic
	errs := callsys(syscallsToCall)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "errors: %v\n", errs)
	}

	os.Exit(0)
}
