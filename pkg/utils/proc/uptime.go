package proc

import (
	"bytes"
	"strconv"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

const (
	procUptime        = "/proc/uptime"
	procUptimeInitBuf = 32 // a round and realistic initial buffer size
)

type ProcUptime struct {
	uptime   float64 // System uptime in seconds (includes suspended time)
	idleTime float64 // Idle time in seconds
}

func GetUptime() (*ProcUptime, error) {
	data, err := ReadFile(procUptime, procUptimeInitBuf)
	if err != nil {
		return nil, errfmt.Errorf("failed to read %s: %v", procUptime, err)
	}

	// Find the space separator in the original data
	spaceIdx := bytes.IndexByte(data, ' ')
	if spaceIdx <= 0 {
		return nil, errfmt.Errorf("invalid format in %s: missing or empty first field", procUptime)
	}

	// Find the end of the second field (trim trailing newline if present)
	endIdx := len(data)
	if data[endIdx-1] == '\n' {
		endIdx--
	}

	// Ensure there's content for the second field
	if spaceIdx+1 >= endIdx {
		return nil, errfmt.Errorf("invalid format in %s: missing or empty second field", procUptime)
	}

	// Parse uptime (first field: 0 to spaceIdx)
	uptime, err := strconv.ParseFloat(string(data[:spaceIdx]), 64)
	if err != nil {
		return nil, errfmt.Errorf("failed to parse uptime from %s: %v", procUptime, err)
	}

	// Parse idle time (second field: spaceIdx+1 to endIdx)
	idleTime, err := strconv.ParseFloat(string(data[spaceIdx+1:endIdx]), 64)
	if err != nil {
		return nil, errfmt.Errorf("failed to parse idle time from %s: %v", procUptime, err)
	}

	return &ProcUptime{
		uptime:   uptime,
		idleTime: idleTime,
	}, nil
}

// GetUptime returns the system uptime (includes suspended time).
func (u *ProcUptime) GetUptime() float64 {
	return u.uptime
}

// GetIdleTime returns the idle time of the system.
func (u *ProcUptime) GetIdleTime() float64 {
	return u.idleTime
}
