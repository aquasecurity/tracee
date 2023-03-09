package flags

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events/queue"
)

func cacheHelp() string {
	return `Select different cache types for the event pipeline queueing.
Possible options:
cache-type={none,mem}                              pick the appropriate cache type.
mem-cache-size=256                                 set memory cache size in MB. only works for cache-type=mem.
Example:
  --cache cache-type=mem                                   | will cache events in memory using default values.
  --cache cache-type=mem --cache mem-cache-size=1024       | will cache events in memory. will set memory cache size to 1024 MB.
  --cache none                                             | no event caching in the pipeline (default).
Use this flag multiple times to choose multiple output options
`
}

func PrepareCache(cacheSlice []string) (queue.CacheConfig, error) {
	var cache queue.CacheConfig
	var err error
	cacheTypeMem := false

	if strings.Contains(cacheSlice[0], "none") {
		return nil, nil
	}

	eventsCacheMemSizeMb := 0
	for _, o := range cacheSlice {
		cacheParts := strings.SplitN(o, "=", 2)
		if len(cacheParts) != 2 {
			return cache, errfmt.Errorf("unrecognized cache option format: %s", o)
		}
		key := cacheParts[0]
		value := cacheParts[1]

		switch key {
		case "cache-type":
			switch value {
			case "mem":
				cacheTypeMem = true
			default:
				return nil, errfmt.Errorf("unrecognized cache-mem option: %s (valid options are: none,mem)", o)
			}
		case "mem-cache-size":
			if !cacheTypeMem {
				return nil, errfmt.Errorf("you need to specify cache-type=mem before setting mem-cache-size")
			}
			eventsCacheMemSizeMb, err = strconv.Atoi(value)
			if err != nil {
				return nil, errfmt.Errorf("could not parse mem-cache-size value: %v", err)
			}

		default:
			return nil, errfmt.Errorf("unrecognized cache option format: %s", o)
		}
	}
	if cacheTypeMem {
		return queue.NewEventQueueMem(eventsCacheMemSizeMb), nil
	}

	return nil, nil
}
