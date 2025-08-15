package system

import (
	"fmt"
	"os"
	"runtime"

	"github.com/aquasecurity/tracee/common/proc"
)

const (
	// Clock ticks per second - standard for most Linux distributions (CONFIG_HZ_100)
	// While some kernels use 250, 300, or 1000 Hz, 100 Hz is correct for 99% of systems
	clockTicksPerSecond = 100.0
)

// CPUStats represents CPU usage information
type CPUStats struct {
	// Raw CPU time values in clock ticks
	UserTime   uint64
	SystemTime uint64
	// System uptime in seconds
	Uptime float64
	// Number of CPU cores
	Cores int
}

// MemoryStats represents memory usage information
type MemoryStats struct {
	// Go runtime memory stats
	Alloc      uint64 // bytes allocated and still in use
	TotalAlloc uint64 // bytes allocated (even if freed)
	Sys        uint64 // bytes obtained from system
	NumGC      uint32 // number of garbage collections
	// RSS memory from /proc/self/status
	RSS uint64 // resident set size in bytes
}

// GetCPUStats returns current CPU usage statistics by reading /proc/self/stat and /proc/uptime
func GetCPUStats() (CPUStats, error) {
	var cpuStats CPUStats

	// Get self stat
	stat, err := proc.NewProcStatFields(
		int32(os.Getpid()),
		[]proc.StatField{
			proc.StatUtime,
			proc.StatStime,
		},
	)
	if err != nil {
		return cpuStats, fmt.Errorf("failed to read process stat: %w", err)
	}

	// Get system uptime
	procUptime, err := proc.GetUptime()
	if err != nil {
		return cpuStats, fmt.Errorf("failed to get uptime: %w", err)
	}

	// Fill CPUStats
	cpuStats.UserTime = stat.GetUserTime()
	cpuStats.SystemTime = stat.GetSystemTime()
	cpuStats.Uptime = procUptime.GetUptime()
	cpuStats.Cores = runtime.NumCPU()

	return cpuStats, nil
}

// GetMemoryStats returns current memory usage statistics including both Go runtime and RSS memory
func GetMemoryStats() MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats := MemoryStats{
		Alloc:      m.Alloc,
		TotalAlloc: m.TotalAlloc,
		Sys:        m.Sys,
		NumGC:      m.NumGC,
	}

	// Get self RSS memory
	rss, _ := getRSSMemory() // Ignore error, RSS will be 0 if failed
	stats.RSS = rss

	return stats
}

// getRSSMemory returns the resident set size (RSS) memory in bytes
func getRSSMemory() (uint64, error) {
	status, err := proc.NewProcStatusFields(
		int32(os.Getpid()),
		[]proc.StatusField{
			proc.VmRSS,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("failed to read process status: %w", err)
	}

	return status.GetVmRSS() * 1024, nil // Convert KB to bytes
}

// CalculateCPUUsagePercent calculates CPU usage percentage between two CPU stat measurements
func CalculateCPUUsagePercent(previous, current CPUStats) float64 {
	if previous.UserTime == 0 && previous.SystemTime == 0 {
		// First measurement, return 0
		return 0
	}

	// Calculate CPU usage rate
	prevTotal := previous.UserTime + previous.SystemTime
	currTotal := current.UserTime + current.SystemTime
	cpuTimeDiff := float64(currTotal - prevTotal)
	uptimeDiff := current.Uptime - previous.Uptime

	if uptimeDiff <= 0 {
		return 0
	}

	// Convert clock ticks to seconds and calculate percentage
	// Use pre-initialized clock ticks per second (set in init())
	cpuSecondsDiff := cpuTimeDiff / clockTicksPerSecond
	return (cpuSecondsDiff / uptimeDiff) * 100.0
}
