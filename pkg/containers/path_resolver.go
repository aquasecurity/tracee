package containers

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/bucketscache"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// ContainerPathResolver generates an accessible absolute path from the root
// mount namespace to a relative path in a container. **NOTE**: to resolve host
// mount namespace, tracee reads from /proc/1/ns, requiring CAP_SYS_PTRACE
// capability.
type ContainerPathResolver struct {
	fs               fs.FS
	mountNSPIDsCache *bucketscache.BucketsCache
}

// InitContainerPathResolver creates a resolver for paths from within
// containers.
func InitContainerPathResolver(mountNSPIDsCache *bucketscache.BucketsCache) *ContainerPathResolver {
	return &ContainerPathResolver{
		fs:               os.DirFS("/"),
		mountNSPIDsCache: mountNSPIDsCache,
	}
}

// GetHostAbsPath translates an absolute path, which might be inside a
// container, to the correspondent abs path in the host mount namespace.
func (cPathRes *ContainerPathResolver) GetHostAbsPath(mountNSAbsolutePath string, mountNS int) (
	string, error,
) {
	var err error

	// path should be absolute, except, for example, memfd_create files
	if mountNSAbsolutePath == "" || mountNSAbsolutePath[0] != '/' {
		return "", errfmt.Errorf("file path is not absolute in its container mount point")
	}

	// Current process has already died, try to access the root fs from another
	// process of the same mount namespace.

	pids := cPathRes.mountNSPIDsCache.GetBucket(uint32(mountNS))

	retMountNSAbsolutePath := ""

	err = capabilities.GetInstance().Requested(
		func() error {

			for _, pid := range pids {
				procRootPath := fmt.Sprintf("/proc/%d/root", int(pid))
				// fs.FS interface requires relative paths, so the '/' prefix should be trimmed.
				entries, err := fs.ReadDir(cPathRes.fs, strings.TrimPrefix(procRootPath, "/"))
				if err != nil {
					return errfmt.WrapError(err)
				}
				if len(entries) == 0 {
					return errfmt.Errorf("empty directory")
				}
				if err == nil {
					retMountNSAbsolutePath = fmt.Sprintf("%s%s", procRootPath, mountNSAbsolutePath)
					return nil
				}
			}
			return errfmt.Errorf("has no access to container fs - no living task of mountns %d", mountNS)

		},
		cap.SYS_PTRACE,
	)
	if err == nil {
		return retMountNSAbsolutePath, nil
	}

	return "", err
}
