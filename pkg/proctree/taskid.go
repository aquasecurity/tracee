package proctree

import (
	"github.com/aquasecurity/tracee/common/murmur"
)

// HashTaskID creates a consistent hash for a task ID (process/thread identifier).
// It rounds the timestamp to USER_HZ precision for compatibility with procfs readings,
// since start_time is measured in clock ticks. The userland precision is defined by
// USER_HZ, which is 100HZ in almost all cases (except embedded systems and custom kernels).
//
// This ensures the process tree can be updated by both eBPF events and procfs readings
// using the same hash for the same task.
func HashTaskID(pid uint32, startTime uint64) uint32 {
	round := startTime / 100000000 // (1000000000 / USER_HZ) * 10 = 100000000
	round *= 100000000
	return murmur.HashU32AndU64(pid, round)
}
