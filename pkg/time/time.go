package time

/*
#include <unistd.h>
*/
import "C"

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
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
			configHZ = utils.RoundToClosestN(int(inferredHz), 50) // round to closest 50Hz (100, 150,...)
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

var initTimeOnce sync.Once    // Set reference times times once
var startTime, bootTime int64 // To normalize times, these should be constant

// Common clock IDs
const (
	CLOCK_MONOTONIC = unix.CLOCK_MONOTONIC // Time since a boot (not including time spent in suspend)
	CLOCK_BOOTTIME  = unix.CLOCK_BOOTTIME  // Time since a boot (including time spent in suspend)
)

// Init sets the reference points for (approximate) system and process start time.
// Run this function ASAP. Not running this function first will cause wrong behaviour
// in other functions of the package.
//
// Reference points can be set from two differents clocks: CLOCK_MONOTONIC or CLOCK_BOOTTIME.
// Tracee bpf code tries to use boottime clock if available, otherwise uses monotonic clock.
// ClockGettime get time elapsed since start (boot) so tracee can calculate event timestamps.
func Init(clockID int32) error {
	var err error
	initTimeOnce.Do(func() {
		startTimeMonotonic, errIn := getClockTimeNS(clockID)
		if errIn != nil {
			err = errIn
			return
		}
		startTimeEpoch := time.Now().UnixNano()

		// process start time since boot
		startTime = startTimeMonotonic

		/*
				Note how the epoch read is just after the monotonic read, allowing us
				to approximate the boot time
				                                               Epoch
			                                                   Read
				---|-----------...-----|-----------...-------|-|--------------------->
				   Epoch               Boot                  Monotonic
			       Start                                     Read
		*/
		// process start time since boot - process start time since epoch = (approx) boot time since epoch
		bootTime = startTimeEpoch - startTimeMonotonic
	})

	return err
}

// GetStartTimeNS sets the constant start time and returns it.

// relative to it.
func GetStartTimeNS() int64 {
	return startTime
}

// GetBootTimeNS returns the boot time of the system in nanoseconds since epoch.
func GetBootTimeNS() int64 {
	return bootTime
}

func GetBootTime() time.Time {
	bootNS := GetBootTimeNS()
	return time.Unix(0, bootNS)
}

func getClockTimeNS(clockID int32) (int64, error) {
	var ts unix.Timespec

	err := unix.ClockGettime(clockID, &ts)
	if err != nil {
		logger.Debugw("error getting time", "err", err)
		return 0, err
	}
	return ts.Nano(), nil
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
