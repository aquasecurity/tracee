package flags

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/proctree"
)

func procTreeHelp() string {
	return `Select different options for the process tree.

Example:
  --proctree source=[none|events|signals|both]
      none         | process tree is disabled (default).
      events       | process tree is built from events.
      signals      | process tree is built from signals.
      both         | process tree is built from both events and signals.
  --proctree process-cache=8192   | will cache up to 8192 processes in the tree (LRU cache).
  --proctree thread-cache=4096    | will cache up to 4096 threads in the tree (LRU cache).
  --proctree disable-procfs       | will disable procfs entirely.
  --proctree disable-procfs-query | will disable procfs quering during runtime.

Use comma OR use the flag multiple times to choose multiple options:
  --proctree source=A,process-cache=B,thread-cache=C
  --proctree process-cache=X --proctree thread-cache=Y
`
}

func PrepareProcTree(cacheSlice []string) (proctree.ProcTreeConfig, error) {
	var err error

	config := proctree.ProcTreeConfig{
		Source:               proctree.SourceNone, // disabled by default
		ProcessCacheSize:     proctree.DefaultProcessCacheSize,
		ThreadCacheSize:      proctree.DefaultThreadCacheSize,
		ProcfsInitialization: true,
		ProcfsQuerying:       true,
	}

	cacheSet := false

	for _, slice := range cacheSlice {
		if strings.HasPrefix(slice, "help") {
			return config, fmt.Errorf(procTreeHelp())
		}
		if strings.HasPrefix(slice, "none") {
			return config, nil
		}

		values := strings.Split(slice, ",")

		for _, value := range values {
			if strings.HasPrefix(value, "source=") {
				option := strings.TrimPrefix(value, "source=")
				switch option {
				case "none":
					config.Source = proctree.SourceNone
				case "events":
					config.Source = proctree.SourceEvents
				case "signals":
					config.Source = proctree.SourceSignals
				case "both":
					config.Source = proctree.SourceBoth
				default:
					return config, fmt.Errorf("unrecognized proctree source option: %v", option)
				}
				if config.Source != proctree.SourceNone {
					cacheSet = true // at least the default ones
				}
				continue
			}
			if strings.HasPrefix(value, "process-cache=") {
				num := strings.TrimPrefix(value, "process-cache=")
				size, err := strconv.Atoi(num)
				if err != nil {
					return config, err
				}
				if size >= 4096 { // minimum size is 4096 (or the default is used)
					config.ProcessCacheSize = size
				}
				cacheSet = true
				continue
			}
			if strings.HasPrefix(value, "thread-cache=") {
				num := strings.TrimPrefix(value, "thread-cache=")
				size, err := strconv.Atoi(num)
				if err != nil {
					return config, err
				}
				if size >= 4096 { // minimum size is 4096 (or the default is used)
					config.ThreadCacheSize = size
				}
				cacheSet = true
				continue
			}
			if value == "disable-procfs" {
				config.ProcfsInitialization = false
				config.ProcfsQuerying = false
				continue
			}
			if value == "disable-procfs-query" {
				config.ProcfsQuerying = false
				continue
			}
			err = fmt.Errorf("unrecognized proctree option format: %v", value)
		}
	}

	if cacheSet && config.Source == proctree.SourceNone {
		return config, fmt.Errorf("proctree cache was set but no source was given")
	}

	if config.Source != proctree.SourceNone {
		logger.Debugw("proctree is enabled and it source is set to", "source", config.Source.String())
		logger.Debugw("proctree cache size", "process", config.ProcessCacheSize, "thread", config.ThreadCacheSize)
	}

	return config, err
}
