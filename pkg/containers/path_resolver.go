package containers

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/bucketscache"
	"os"
	"strconv"
)

// ContainersPathResolver generate an accessible absolute path to a a relative path in a container
type ContainersPathResolver struct {
	mountNSPIDsCache *bucketscache.BucketsCache
}

func InitContainersPathReslover(mountNSPIDsCache *bucketscache.BucketsCache) ContainersPathResolver {
	return ContainersPathResolver{
		mountNSPIDsCache: mountNSPIDsCache,
	}
}

func (cPathRes ContainersPathResolver) ResolveAbsolutePath(relativePath string, mountNS int) (string, error) {
	// path should be absolute, except for e.g memfd_create files
	if relativePath == "" || relativePath[0] != '/' {
		return "", fmt.Errorf("file path is not absolute in its container mount point")
	}
	// try to access the root fs via another process in the same mount namespace (since the current process might have already died)
	pids := cPathRes.mountNSPIDsCache.GetBucket(uint32(mountNS))
	var absolutePath string
	for _, pid := range pids {
		procRootPath := fmt.Sprintf("/proc/%s/root", strconv.Itoa(int(pid)))
		_, err := os.Stat(procRootPath)
		if err == nil {
			absolutePath = fmt.Sprintf("%s%s", procRootPath, relativePath)
			break
		}
	}
	if absolutePath == "" {
		return "", fmt.Errorf("has no access to container fs - no recorded living process of mount namespace %d", mountNS)
	}
	return fmt.Sprintf("/proc/%s/root%s", strconv.Itoa(int(pids[0])), relativePath), nil

}
