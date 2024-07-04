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

var configHZOnce, clockTickOnce, bootTimeOnce sync.Once
var configHZ int
var userHZ int64
var bootTime int64 // To normalize times, this should be constant

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

// Common clock IDs
const (
	CLOCK_MONOTONIC = unix.CLOCK_MONOTONIC // Time since a boot (not including time spent in suspend)
	CLOCK_BOOTTIME  = unix.CLOCK_BOOTTIME  // Time since a boot (including time spent in suspend)
)

// GetStartTimeNS returns the elapsed time since system start in nanoseconds.
// Possible to retrieve from two differents clocks: CLOCK_MONOTONIC or CLOCK_BOOTTIME.
func GetStartTimeNS(clockID int32) int64 {
	var ts unix.Timespec

	// Tracee bpf code try to use boottime clock if available, otherwise uses monotonic clock.
	// ClockGettime get time elapsed since start (boot) so tracee can calculate event timestamps
	// relative to it.
	err := unix.ClockGettime(clockID, &ts)
	if err != nil {
		logger.Debugw("error getting time", "err", err)
		return 0
	}
	return ts.Nano()
}

// GetBootTimeNS returns the boot time of the system in nanoseconds.
func GetBootTimeNS(clockID int32) int64 {
	bootTimeOnce.Do(
		func() {
			startTime := GetStartTimeNS(clockID)
			bootTime = time.Now().UnixNano() - startTime
		})
	return bootTime
}

func GetBootTime(clockID int32) time.Time {
	startTime := GetStartTimeNS(clockID)
	uptime := time.Duration(startTime) * time.Nanosecond
	return time.Now().Add(-uptime)
}

//
// Time conversions functions
//

// ClockTicksToNsSinceBootTime converts kernel clock ticks to nanoseconds.
func ClockTicksToNsSinceBootTime(ticks int64) uint64 {
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
	return uint64(ticks * 1000000000 / GetUserHZ())
}

// NsSinceBootTimeToTime converts nanoseconds timestamp (since boot) to a time.Time object.
func NsSinceBootTimeToTime(clockID int32, ns uint64) time.Time {
	duration := time.Duration(int64(ns))
	bootTime := GetBootTime(clockID)
	return bootTime.Add(duration)
}

func NsSinceEpochToTime(ns uint64) time.Time {
	return time.Unix(0, int64(ns))
}
