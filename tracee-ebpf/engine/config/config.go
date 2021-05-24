package config

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/consts"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/filters"
	"os"
)

// Config is a struct containing user defined configuration of tracee
type Config struct {
	Filter             *filters.Filter
	Capture            *CaptureConfig
	Output             *OutputConfig
	PerfBufferSize     int
	BlobPerfBufferSize int
	SecurityAlerts     bool
	MaxPidsCache       int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BPFObjPath         string
}

type CaptureConfig struct {
	OutputPath      string
	FileWrite       bool
	FilterFileWrite []string
	Exec            bool
	Mem             bool
	Profile         bool
}

func (cfg *Config) Validate() error {
	if cfg.Filter.EventsToTrace == nil {
		return fmt.Errorf("eventsToTrace is nil")
	}

	for _, e := range cfg.Filter.EventsToTrace {
		if _, ok := consts.EventsIDToEvent[e]; !ok {
			return fmt.Errorf("invalid event to trace: %d", e)
		}
	}
	for eventID, eventFilters := range cfg.Filter.ArgFilter.Filters {
		for argName := range eventFilters {
			eventParams, ok := consts.EventsIDToParams[eventID]
			if !ok {
				return fmt.Errorf("invalid argument filter event id: %d", eventID)
			}
			// check if argument name exists for this event
			argFound := false
			for i := range eventParams {
				if eventParams[i].Name == argName {
					argFound = true
					break
				}
			}
			if !argFound {
				return fmt.Errorf("invalid argument filter argument name: %s", argName)
			}
		}
	}
	if (cfg.PerfBufferSize & (cfg.PerfBufferSize - 1)) != 0 {
		return fmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if (cfg.BlobPerfBufferSize & (cfg.BlobPerfBufferSize - 1)) != 0 {
		return fmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if len(cfg.Capture.FilterFileWrite) > 3 {
		return fmt.Errorf("too many file-write filters given")
	}
	for _, filter := range cfg.Capture.FilterFileWrite {
		if len(filter) > 50 {
			return fmt.Errorf("the length of a path filter is limited to 50 characters: %s", filter)
		}
	}
	_, err := os.Stat(cfg.BPFObjPath)
	if err == nil {
		return err
	}

	err = cfg.Output.Validate()
	if err != nil {
		return err
	}
	return nil
}
