package containers

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/bucketscache"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
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
	// path should be absolute, except, for example, memfd_create files
	if mountNSAbsolutePath == "" || mountNSAbsolutePath[0] != '/' {
		return "", ErrNonAbsolutePath
	}

	// Current process has already died, try to access the root fs from another
	// process of the same mount namespace.
	pids := cPathRes.mountNSPIDsCache.GetBucket(uint32(mountNS))

	for _, pid := range pids {
		procRoot, err := cPathRes.getProcessFSRoot(uint(pid))
		if err != nil {
			// Try next pid in mount ns to find accessible path to mount ns files.
			logger.Debugw("Could not access process FS", "pid", pid, "error", err)
			continue
		}

		return fmt.Sprintf("%s%s", procRoot, mountNSAbsolutePath), nil
	}

	// No PIDs registered in this namespace, or couldn't access FS root of any of the PIDs found.
	// Try finding one in procfs.
	pid, err := proc.GetAnyProcessInNS("mnt", mountNS)
	if err != nil {
		// Couldn't find a process in this namespace using procfs
		return "", ErrContainerFSUnreachable
	}

	procRoot, err := cPathRes.getProcessFSRoot(pid)
	if err != nil {
		logger.Debugw("Could not access process FS", "pid", pid, "error", err)
		return "", ErrContainerFSUnreachable
	}

	// Register this process in the mount namespace
	cPathRes.mountNSPIDsCache.AddBucketItem(uint32(mountNS), uint32(pid))

	return fmt.Sprintf("%s%s", procRoot, mountNSAbsolutePath), nil
}

func (cPathRes *ContainerPathResolver) getProcessFSRoot(pid uint) (string, error) {
	// cap.SYS_PTRACE is needed here. Instead of raising privileges, since
	// this is called too frequently, if the needed event is being traced,
	// the needed capabilities are added to the Base ring and are always set
	// as effective.
	//
	// (Note: To change this behavior we need a privileged process/server)

	procRootPath := fmt.Sprintf("/proc/%d/root", pid)

	// fs.FS interface requires relative paths, so the '/' prefix should be trimmed.
	entries, err := fs.ReadDir(cPathRes.fs, strings.TrimPrefix(procRootPath, "/"))
	if err != nil {
		// This process is either not alive or we don't have permissions to access.
		return "", errfmt.Errorf("failed accessing process FS root %s: %v", procRootPath, err)
	}
	if len(entries) == 0 {
		return "", errfmt.Errorf("process FS root (%s) is empty", procRootPath)
	}

	return procRootPath, nil
}

var (
	ErrContainerFSUnreachable = errors.New("container file system is unreachable in mount namespace because there are not living children")
	ErrNonAbsolutePath        = errors.New("file path is not absolute in its container mount point")
)
