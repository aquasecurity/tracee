package flags

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"strconv"
	"strings"
)

func CacheHelp() string {
	return `Select different cache types for the event pipeline queueing.
Possible options:
cache-type={none,mem}                              pick the appropriate cache type.
mem-cache-size=256                                 set memory cache size in MB. only works for cache-type=mem.
Example:
  --cache cache-type=mem                                   | will cache events in memory using default values.
  --cache cache-type=mem --cache mem-cache-size=1024       | will cache events in memory. will set memory cache size to 1GB.
  --cache none                                             | no event caching in the pipeline (default).
Use this flag multiple times to choose multiple output options
`
}

func PrepareCache(cacheSlice []string) (queue.CacheConfig, error) {
	var cache queue.CacheConfig
	var err error
	set := false

	if strings.Contains(cacheSlice[0], "none") {
		return nil, nil
	}

	for _, o := range cacheSlice {
		cacheParts := strings.SplitN(o, "=", 2)
		if len(cacheParts) != 2 {
			return cache, fmt.Errorf("unrecognized cache option format: %s", o)
		}
		key := cacheParts[0]
		value := cacheParts[1]

		switch key {
		case "cache-type":
			switch value {
			case "mem":
				cache = &queue.EventQueueMem{}
				set = true
			default:
				return nil, fmt.Errorf("unrecognized cache-mem option: %s (valid options are: none,mem)", o)
			}
		case "mem-cache-size":
			if v, ok := cache.(*queue.EventQueueMem); ok {
				v.EventsCacheMemSizeMB, err = strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("could not parse mem-cache-size value: %v", err)
				}
				break
			}
			return nil, fmt.Errorf("you need to specify cache-type=mem before setting mem-cache-size")
		default:
			return cache, fmt.Errorf("unrecognized cache option format: %s", o)
		}
	}
	if set {
		return cache, nil
	}

	return nil, nil
}
