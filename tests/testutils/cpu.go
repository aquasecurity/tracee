package testutils

import (
	"golang.org/x/sys/unix"
)

const CPUForTests = 0 // CPU to pin test processes to

// PinProccessToCPU pins the current process to a specific CPU
func PinProccessToCPU(id ...int) error {
	if len(id) == 0 {
		id = append(id, CPUForTests)
	}

	cpuMask := unix.CPUSet{}
	for _, i := range id {
		cpuMask.Set(i)
	}

	return unix.SchedSetaffinity(0, &cpuMask)
}
