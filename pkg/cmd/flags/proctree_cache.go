package flags

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/proctree"
)

func procTreeHelp() string {
	return `Select different cache sizes for the process tree.

Example:
  --proctree process=8192 	    | will cache up to 8192 processes in the tree (LRU cache).
  --proctree thread=4096  	    | will cache up to 4096 threads in the tree (LRU cache).

Use comma OR use the flag multiple times to choose multiple options:
  --proctree process=X,thread=Y
  --proctree process=X --proctree thread=Y
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
			logger.Debugw("proctree cache has default size")
			return config, nil
		}

		values := strings.Split(slice, ",")

		for _, value := range values {
			if strings.HasPrefix(value, "process=") {
				num := strings.TrimPrefix(value, "process=")
				size, err := strconv.Atoi(num)
				if err != nil {
					return config, err
				}
				if size > 4096 { // minimum size is 4096 (or the default is used)
					config.ProcessCacheSize = size
				}
				continue
			}
			if strings.HasPrefix(value, "thread=") {
				num := strings.TrimPrefix(value, "thread=")
				size, err := strconv.Atoi(num)
				if err != nil {
					return config, err
				}
				if size > 4096 { // minimum size is 4096 (or the default is used)
					config.ThreadCacheSize = size
				}
				continue
			}
			err = fmt.Errorf("unrecognized proctree option format: %v", value)
		}
	}

	logger.Debugw("proctree cache size", "process", config.ProcessCacheSize, "thread", config.ThreadCacheSize)

	return config, err
}
