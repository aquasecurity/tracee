package flags

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/dnscache"
)

func dnsCacheHelp() string {
	return `Select different options for the DNS cache.

Example:
  --dnscache enable  | enable with default values (see below).
  --dnscache size=X  | will cache up to X dns query trees - further queries may be cached regardless (default: 5000).

Use comma OR use the flag multiple times to choose multiple options:
  --dnscache size=A
  --dnscache enable
`
}

func PrepareDnsCache(cacheSlice []string) (dnscache.Config, error) {
	var err error

	config := dnscache.Config{
		Enable:    true, // assume enabled and return disabled if no flag given
		CacheSize: dnscache.DefaultCacheSize,
	}

	for _, slice := range cacheSlice {
		if strings.HasPrefix(slice, "help") {
			return config, fmt.Errorf(dnsCacheHelp())
		}
		if slice == "enable" {
			continue
		}
		if slice == "none" {
			// no flag given
			config.Enable = false
			return config, nil
		}

		values := strings.Split(slice, ",")

		for _, value := range values {
			if strings.HasPrefix(value, "size=") {
				num := strings.TrimPrefix(value, "size=")
				size, err := strconv.Atoi(num)
				if err != nil {
					return config, err
				}
				config.CacheSize = size
				config.Enable = true
				continue
			}
			err = fmt.Errorf("unrecognized dnscache option format: %v", value)
		}
	}

	return config, err
}
