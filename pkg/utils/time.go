package utils

/*
#include <unistd.h>
*/
import "C"

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
)

var configHZOnce, clockTickOnce sync.Once
var realHz int
var tickHz int64

// GetBootTime returns the boot time of the system as a time.Time object.
func GetBootTime() time.Time {
	var si syscall.Sysinfo_t
	err := syscall.Sysinfo(&si)
	if err != nil {
		logger.Debugw("error getting boot time", "err", err)
		return time.Time{}
	}
	uptime := time.Duration(si.Uptime) * time.Second
	return time.Now().Add(-uptime)
}

// GetKernelConfigHZ returns an approximation of the kernel's HZ (the kernel timer interrupt), w/out
// reading kernel config file (which may not be available).
func GetKernelConfigHZ() int {
	configHZOnce.Do(
		func() {
			jiffiesStart := getBootTimeInJiffies()
			time.Sleep(time.Second)
			jiffiesEnd := getBootTimeInJiffies()
			inferredHz := jiffiesEnd - jiffiesStart
			realHz = RoundToClosestN(int(inferredHz), 50) // round to closest 50Hz (100, 150,...)
		},
	)
	return realHz
}

// GetSystemClockTicks Get the system clock ticks per second (HZ value). The system clock ticks is
// USER_HZ for the kernel, which is 100HZ in almost all cases (untrue for embedded systems and
// custom builds).
func GetSystemClockTicks() int64 {
	clockTickOnce.Do(
		func() {
			tickHz = int64(C.sysconf(C._SC_CLK_TCK))
		},
	)
	return tickHz
}

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
	return uint64(ticks * 1000000000 / GetSystemClockTicks())
}

// NsSinceBootTimeToTime converts nanoseconds timestamp (since boot) to a time.Time object.
func NsSinceBootTimeToTime(ns uint64) time.Time {
	duration := time.Duration(int64(ns))
	bootTime := GetBootTime()
	return bootTime.Add(duration)
}

// Private

// getBootTimeInJiffies returns the boot time of the system in jiffies.
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
