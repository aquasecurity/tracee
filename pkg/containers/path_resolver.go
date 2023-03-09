package containers

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/bucketscache"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// ContainerPathResolver generates an accessible absolute path from the root mount namespace to a
// relative path in a container. **NOTE**: to resolve host mount namespace, tracee reads from
// /proc/1/ns, requiring CAP_SYS_PTRACE capability.
type ContainerPathResolver struct {
	fs               fs.FS
	mountNSPIDsCache *bucketscache.BucketsCache
}

// InitContainerPathResolver creates a resolver for paths from within containers.
func InitContainerPathResolver(mountNSPIDsCache *bucketscache.BucketsCache) *ContainerPathResolver {
	return &ContainerPathResolver{
		fs:               os.DirFS("/"),
		mountNSPIDsCache: mountNSPIDsCache,
	}
}

// GetHostAbsPath translates an absolute path, which might be inside a container, to the
// correspondent abs path in the host mount namespace.
func (cPathRes *ContainerPathResolver) GetHostAbsPath(mountNSAbsolutePath string, mountNS int) (
	string, error,
) {
	// path should be absolute, except, for example, memfd_create files
	if mountNSAbsolutePath == "" || mountNSAbsolutePath[0] != '/' {
		return "", errfmt.Errorf("file path is not absolute in its container mount point")
	}
	// try to access the root fs via another process in the same mount namespace
	// (since the current process might have already died)
	pids := cPathRes.mountNSPIDsCache.GetBucket(uint32(mountNS))
	for _, pid := range pids {
		procRootPath := fmt.Sprintf("/proc/%d/root", int(pid))
		// fs.FS interface requires relative paths, so the '/' prefix should be trimmed.
		err := capabilities.GetInstance().Required(func() error {
			entries, err := fs.ReadDir(cPathRes.fs, strings.TrimPrefix(procRootPath, "/"))
			if err != nil {
				return errfmt.WrapError(err)
			}
			if len(entries) == 0 {
				return errfmt.Errorf("empty directory")
			}
			return nil
		})
		if err == nil {
			return fmt.Sprintf("%s%s", procRootPath, mountNSAbsolutePath), nil
		}
	}
	return "", errfmt.Errorf("has no access to container fs - no living task of mountns %d", mountNS)
}
