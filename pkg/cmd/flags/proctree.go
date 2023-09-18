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
  --proctree enabled            | will enable the process tree with default settings (disabled by default).
  --proctree process-cache=8192 | will cache up to 8192 processes in the tree (LRU cache).
  --proctree thread-cache=4096  | will cache up to 4096 threads in the tree (LRU cache).

Use comma OR use the flag multiple times to choose multiple options:
  --proctree process-cache=X,thread-cache=Y
  --proctree process-cache=X --proctree thread-cache=Y
`
}

func PrepareProcTree(cacheSlice []string) (proctree.ProcTreeConfig, error) {
	var err error

	config := proctree.ProcTreeConfig{
		ProcessCacheSize: proctree.DefaultProcessCacheSize,
		ThreadCacheSize:  proctree.DefaultThreadCacheSize,
	}

	for _, slice := range cacheSlice {
		if strings.HasPrefix(slice, "help") {
			return config, fmt.Errorf(procTreeHelp())
		}
		if strings.HasPrefix(slice, "none") {
			return config, nil
		}

		values := strings.Split(slice, ",")

		for _, value := range values {
			if strings.HasPrefix(value, "enabled") {
				logger.Debugw("proctree is enabled")
				config.Enabled = true
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
				config.Enabled = true
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
				config.Enabled = true
				continue
			}
			err = fmt.Errorf("unrecognized proctree option format: %v", value)
		}
	}

	if config.Enabled {
		logger.Debugw("proctree cache size", "process", config.ProcessCacheSize, "thread", config.ThreadCacheSize)
	}

	return config, err
}
