package timeutil

/*
#include <unistd.h>
*/
import "C"

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/common/logger"
)

var configHZOnce, clockTickOnce sync.Once
var configHZ int
var userHZ int64

// GetSystemHZ returns an approximation of CONFIG_HZ (the kernel timer interrupt).
func GetSystemHZ() int {
	configHZOnce.Do(
		func() {
			jiffiesStart := getBootTimeInJiffies()
			time.Sleep(time.Second)
			jiffiesEnd := getBootTimeInJiffies()
			inferredHz := jiffiesEnd - jiffiesStart
			configHZ = roundToClosestN(int(inferredHz), 50) // round to closest 50Hz (100, 150,...)
		},
	)
	return configHZ // CONFIG_HZ
}

// GetUserHZ returns USER_HZ (the user-space timer interrupt), the system clock tick rate.
func GetUserHZ() int64 {
	// USER_HZ is 100HZ in almost all cases (untrue for embedded and custom builds).
	clockTickOnce.Do(
		func() {
			userHZ = int64(C.sysconf(C._SC_CLK_TCK))
		},
	)
	return userHZ // USER_HZ
}

func getBootTimeInJiffies() int64 {
	data, err := os.ReadFile("/proc/timer_list")
	if err != nil {
		logger.Debugw("error reading /proc/timer_list", "err", err)
		return 0
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "jiffies:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				bootTimeInJiffies, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					logger.Debugw("error parsing jiffies value", "err", err)
					continue
				}
				return bootTimeInJiffies
			}
		}
	}
	logger.Debugw("jiffies value not found")

	return 0
}

//
// Boot time functions
//

var initTimeOnce sync.Once  // Set reference times times once
var startTime int64         // Process start time (in BPF clock base)
var bootTime int64          // Boot time using BPF clock base (for backward compatibility)
var bootTimeBoottime int64  // Boot time using BOOTTIME clock (for procfs conversion)
var bootTimeMonotonic int64 // Boot time using MONOTONIC clock
var usedClockID int32       // Clock ID used for BPF time functions (MONOTONIC or BOOTTIME)

// Common clock IDs
const (
	CLOCK_MONOTONIC = unix.CLOCK_MONOTONIC // Time since a boot (not including time spent in suspend)
	CLOCK_BOOTTIME  = unix.CLOCK_BOOTTIME  // Time since a boot (including time spent in suspend)
)

// Init sets the reference points for (approximate) system and process start time.
// Run this function ASAP. Not running this function first will cause wrong behaviour
// in other functions of the package.
//
// Reference points can be set from two different clocks: CLOCK_MONOTONIC or CLOCK_BOOTTIME.
// Tracee bpf code tries to use boottime clock if available, otherwise uses monotonic clock.
// ClockGettime get time elapsed since start (boot) so tracee can calculate event timestamps.
func Init(clockID int32) error {
	var err error
	initTimeOnce.Do(func() {
		// Store the clock ID for later use (e.g., procfs conversion)
		usedClockID = clockID

		var monotonicNs, boottimeNs int64

		/*
			Boot Time Calculation Strategy
			================================

			We need to convert "time since boot" (from BPF and procfs) to "time since epoch".
			The formula is: epoch_time = boot_time + time_since_boot
			Therefore: boot_time = epoch_time - time_since_boot

			Challenge: We need boot_time for BOTH CLOCK_MONOTONIC and CLOCK_BOOTTIME because:
			- BPF uses one clock (MONOTONIC or BOOTTIME, detected at runtime)
			- Procfs ALWAYS uses BOOTTIME (via jiffies in /proc/[pid]/stat)

			Sequential Read Timeline (minimizing drift):
			--------------------------------------------

			Example when BPF uses CLOCK_MONOTONIC:

			  time →
			  ---|-------------|----------------|--------------->
			     ↑             ↑                ↑
			  Epoch Read   MONOTONIC Read   BOOTTIME Read
			  (reference)    (for BPF)      (for procfs)

			Calculations (all relative to the same epoch reference):
			  boot_time_monotonic = epoch_time - monotonic_ns
			  boot_time_boottime  = epoch_time - boottime_ns

			Note: There's inherent drift between reads (~microseconds), but we:
			1. Minimize it by reading clocks sequentially without delays
			2. Use the SAME epoch reference for all boot time calculations
			3. Accept that boot times are approximations (good enough for our use case)

			The drift is acceptable because:
			- Process start times have millisecond-level precision
			- Hash calculations remain consistent (same clock base throughout)
			- Procfs conversion uses dynamic suspend time to handle clock differences
		*/

		// Get epoch time first for consistent reference
		startTimeEpoch := time.Now().UnixNano()

		// Get the current time in the BPF clock base
		startTimeBpf, errClockBase := getClockTimeNS(clockID)

		// Calculate BOTH clock boot times for procfs conversion
		// This allows us to convert procfs (always BOOTTIME) correctly
		// regardless of which clock BPF uses.

		if clockID == CLOCK_MONOTONIC {
			// Read BOOTTIME (only one we don't have yet)
			boottimeNs, err = getClockTimeNS(CLOCK_BOOTTIME)
			if err != nil {
				return
			}

			// BPF uses MONOTONIC, reuse the value we already read
			monotonicNs = startTimeBpf
		} else {
			// Read MONOTONIC (only one we don't have yet)
			monotonicNs, err = getClockTimeNS(CLOCK_MONOTONIC)
			if err != nil {
				return
			}

			// BPF uses BOOTTIME, reuse the value we already read
			boottimeNs = startTimeBpf
		}

		// Check error only after all clock reads are done, minimizing drift
		if errClockBase != nil {
			err = errClockBase
			return
		}

		// Calculate boot time for the BPF clock base
		// boot_time = epoch_now - time_since_boot
		startTime = startTimeBpf
		bootTime = startTimeEpoch - startTimeBpf

		// Calculate boot times for both clocks
		// All use the same epoch reference for consistency
		bootTimeMonotonic = startTimeEpoch - monotonicNs
		bootTimeBoottime = startTimeEpoch - boottimeNs
	})

	return err
}

// GetStartTimeNS sets the constant start time and returns it.

// relative to it.
func GetStartTimeNS() int64 {
	return startTime
}

// GetBootTimeNS returns the boot time of the system in nanoseconds since epoch.
// This uses the BPF clock base (whatever was passed to Init).
func GetBootTimeNS() int64 {
	return bootTime
}

// GetBootTimeBoottimeNS returns the boot time calculated using CLOCK_BOOTTIME.
// This is used for procfs conversions, which are always BOOTTIME-based.
func GetBootTimeBoottimeNS() int64 {
	return bootTimeBoottime
}

// GetBootTimeMonotonicNS returns the boot time calculated using CLOCK_MONOTONIC.
// Exposed for testing and potential future use.
func GetBootTimeMonotonicNS() int64 {
	return bootTimeMonotonic
}

func GetBootTime() time.Time {
	bootNS := GetBootTimeNS()
	return time.Unix(0, bootNS)
}

func getClockTimeNS(clockID int32) (int64, error) {
	var ts unix.Timespec
	err := unix.ClockGettime(clockID, &ts)

	return ts.Nano(), err
}

//
// Time conversions functions
//

// ClockTicksToNsSinceBootTime converts kernel clock ticks to nanoseconds.
func ClockTicksToNsSinceBootTime(ticks uint64) uint64 {
	// From the man page proc(5):
	//
	// starttime:
	//
	// The time the process started after system boot.
	// Before Linux 2.6, this value was expressed in
	// jiffies.  Since Linux 2.6, the value is expressed
	// in clock ticks (divide by sysconf(_SC_CLK_TCK)).
	//
	// The format for this field was %lu before Linux 2.6.
	return ticks * 1000000000 / uint64(GetUserHZ())
}

// BootToEpochNS converts time since boot to the epoch time
func BootToEpochNS(ns uint64) uint64 {
	return uint64(GetBootTimeNS()) + ns
}

// EpochToBootTimeNS converts time since epoch to relative time from boot
func EpochToBootTimeNS(ns uint64) uint64 {
	return ns - uint64(GetBootTimeNS())
}

// NsSinceBootTimeToTime converts nanoseconds timestamp (since boot) to a time.Time object.
func NsSinceBootTimeToTime(ns uint64) time.Time {
	duration := time.Duration(int64(ns))
	bootTime := GetBootTime()
	return bootTime.Add(duration)
}

func NsSinceEpochToTime(ns uint64) time.Time {
	return time.Unix(0, int64(ns))
}

//
// Procfs conversion functions (clock-aware)
//

// GetUsedClockID returns the clock ID that was set during Init().
// Returns CLOCK_BOOTTIME or CLOCK_MONOTONIC.
func GetUsedClockID() int32 {
	return usedClockID
}

// ProcfsStartTimeToEpochNS converts a /proc/PID/stat starttime (jiffies, BOOTTIME)
// to epoch nanoseconds using the same clock base as BPF.
//
// The /proc/PID/stat field 22 is ALWAYS in BOOTTIME clock (jiffies since boot,
// including suspend time). However, BPF might use MONOTONIC clock (excluding
// suspend time) on kernels where BPF_FUNC_ktime_get_boot_ns is unavailable.
//
// This function ensures the procfs starttime matches the BPF clock base for
// consistent hash calculation.
func ProcfsStartTimeToEpochNS(startTimeJiffies uint64) uint64 {
	// Step 1: Convert jiffies to nanoseconds (time since boot in BOOTTIME base)
	bootNs := ClockTicksToNsSinceBootTime(startTimeJiffies)

	// Step 2: Convert to epoch time using stored BOOTTIME boot time
	// Procfs values are always BOOTTIME-based, so we use GetBootTimeBoottimeNS()
	// regardless of which clock BPF uses
	epochBootNs := uint64(GetBootTimeBoottimeNS()) + uint64(bootNs)

	// Step 3: If BPF uses MONOTONIC, convert BOOTTIME epoch to MONOTONIC epoch
	if usedClockID == CLOCK_MONOTONIC {
		// We must use CURRENT suspend time, not the Init-time value.
		// Suspend time can increase if the system suspends after Init().
		// Procfs values always reflect current suspend time, so we need to
		// match that when converting to MONOTONIC.
		suspendNs, err := getCurrentSuspendTime()
		if err != nil {
			// Fallback: If we can't get current suspend time, return BOOTTIME value.
			// This may cause hash mismatch but is better than crash.
			logger.Debugw("Failed to get current suspend time for procfs conversion", "error", err)
			return epochBootNs
		}

		return convertBoottimeToMonotonicEpoch(epochBootNs, suspendNs)
	}

	// BPF uses BOOTTIME, no conversion needed
	return epochBootNs
}

// convertBoottimeToMonotonicEpoch converts a BOOTTIME epoch timestamp to MONOTONIC
// epoch timestamp by subtracting the given suspend time.
//
// Formula: MONOTONIC = BOOTTIME - SUSPEND_TIME
//
// Parameters:
//   - boottimeEpochNs: Timestamp in BOOTTIME base (nanoseconds since epoch)
//   - suspendNs: Current system suspend time in nanoseconds
//
// Returns: Timestamp in MONOTONIC base (nanoseconds since epoch)
func convertBoottimeToMonotonicEpoch(boottimeEpochNs uint64, suspendNs uint64) uint64 {
	// Subtract suspend time: MONOTONIC = BOOTTIME - SUSPEND
	if boottimeEpochNs >= suspendNs {
		return boottimeEpochNs - suspendNs
	}

	// Edge case: suspend time > boottime timestamp (very old process or error)
	// Return as-is to avoid underflow
	return boottimeEpochNs
}

// getCurrentSuspendTime calculates the current system suspend time in nanoseconds.
//
// Suspend time is the difference between BOOTTIME and MONOTONIC clocks:
//   - BOOTTIME: Time since boot, INCLUDING time spent in suspend
//   - MONOTONIC: Time since boot, EXCLUDING time spent in suspend
//   - SUSPEND = BOOTTIME - MONOTONIC
//
// This function must read the CURRENT suspend time because it can increase if the
// system suspends after Init(). The stored value (bootTimeMonotonic - bootTimeBoottime)
// would only be accurate if suspend time never changed, which is not guaranteed.
func getCurrentSuspendTime() (uint64, error) {
	var boottime unix.Timespec
	var monotonic unix.Timespec
	var err1, err2 error

	// Get current clocks first, check for errors later.
	err1 = unix.ClockGettime(unix.CLOCK_BOOTTIME, &boottime)
	err2 = unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic)

	if err1 != nil {
		return 0, fmt.Errorf("failed to get BOOTTIME: %v", err1)
	}
	if err2 != nil {
		return 0, fmt.Errorf("failed to get MONOTONIC: %v", err2)
	}

	// Convert to nanoseconds
	boottimeNs := uint64(boottime.Sec)*1e9 + uint64(boottime.Nsec)
	monotonicNs := uint64(monotonic.Sec)*1e9 + uint64(monotonic.Nsec)

	// Calculate suspend time: SUSPEND = BOOTTIME - MONOTONIC
	if boottimeNs >= monotonicNs {
		return boottimeNs - monotonicNs, nil
	}

	// This should not happen in practice, but it's a sanity check.
	logger.Debugw("Clock anomaly: MONOTONIC > BOOTTIME", "boottimeNs", boottimeNs, "monotonicNs", monotonicNs)
	return 0, nil // Return 0 to avoid underflow
}

// roundToClosestN rounds a number to the closest multiple of n.
func roundToClosestN(val int, n int) int {
	return int(math.Round(float64(val)/float64(n))) * n
}

// GenerateRandomDuration returns a random duration between min and max, inclusive
func GenerateRandomDuration(min, max int) time.Duration {
	return time.Duration(rand.Intn(max-min+1)+min) * time.Second
}
