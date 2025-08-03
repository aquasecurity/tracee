package containers

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

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
	// symlinkCache caches symlink resolution results to improve performance (LRU with size limit)
	symlinkCache *lru.Cache[string, string]
}

// InitContainerPathResolver creates a resolver for paths from within
// containers.
func InitContainerPathResolver(mountNSPIDsCache *bucketscache.BucketsCache) *ContainerPathResolver {
	// Create LRU cache for symlink resolutions (1024 entries should be sufficient for most workloads)
	symlinkCache, err := lru.New[string, string](1024)
	if err != nil {
		logger.Errorw("Failed to create symlink cache, using uncached resolution", "error", err)
		symlinkCache = nil
	}

	return &ContainerPathResolver{
		fs:               os.DirFS("/"),
		mountNSPIDsCache: mountNSPIDsCache,
		symlinkCache:     symlinkCache,
	}
}

// GetHostAbsPath translates an absolute path, which might be inside a
// container, to the correspondent abs path in the host mount namespace.
func (cPathRes *ContainerPathResolver) GetHostAbsPath(mountNSAbsolutePath string, mountNS uint32) (
	string, error,
) {
	// Validate inputs
	if mountNSAbsolutePath == "" || mountNSAbsolutePath[0] != '/' {
		return "", ErrNonAbsolutePath
	}
	if mountNS == 0 {
		return "", errfmt.Errorf("invalid mount namespace ID: %d", mountNS)
	}

	// Current process has already died, try to access the root fs from another
	// process of the same mount namespace.
	pids := cPathRes.mountNSPIDsCache.GetBucket(mountNS)

	for _, pid := range pids {
		procFSRoot, err := cPathRes.getProcessFSRoot(uint(pid))
		if err != nil {
			// Try next pid in mount ns to find accessible path to mount ns files.
			logger.Debugw("Could not access process FS", "pid", pid, "error", err)
			continue
		}

		return filepath.Join(procFSRoot, mountNSAbsolutePath), nil
	}

	// No PIDs registered in this namespace, or couldn't access FS root of any of the PIDs found.
	// Try finding one in procfs.
	pid, err := proc.GetAnyProcessInNS("mnt", mountNS)
	if err != nil {
		// Couldn't find a process in this namespace using procfs
		return "", ErrContainerFSUnreachable
	}

	procFSRoot, err := cPathRes.getProcessFSRoot(uint(pid))
	if err != nil {
		return "", errfmt.Errorf("could not access process %d FS: %v", pid, err)
	}

	// register this process in the mount namespace
	cPathRes.mountNSPIDsCache.AddBucketItem(mountNS, uint32(pid))

	return filepath.Join(procFSRoot, mountNSAbsolutePath), nil
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

// ResolveLink resolves a single symlink to its final destination within the specified mount namespace.
// It follows symlinks until it reaches a non-symlink target or detects a loop.
// The resolution is performed from the perspective of the mount namespace, ensuring
// security by validating that resolved paths don't escape the namespace boundary.
//
// Parameters:
//   - mountNSAbsolutePath: absolute path within the mount namespace
//   - mountNS: mount namespace ID
//
// Returns the resolved path within the mount namespace context.
func (cPathRes *ContainerPathResolver) ResolveLink(mountNSAbsolutePath string, mountNS uint32) (
	string, error,
) {
	// Validate inputs
	if mountNSAbsolutePath == "" || mountNSAbsolutePath[0] != '/' {
		return "", ErrNonAbsolutePath
	}
	if mountNS == 0 {
		return "", errfmt.Errorf("invalid mount namespace ID: %d", mountNS)
	}

	// Check cache first (if available)
	cacheKey := fmt.Sprintf("%d:%s", mountNS, mountNSAbsolutePath)
	if cPathRes.symlinkCache != nil {
		if cached, exists := cPathRes.symlinkCache.Get(cacheKey); exists {
			return cached, nil
		}
	}

	nsRootPath, err := cPathRes.GetHostAbsPath("/", mountNS)
	if err != nil {
		return "", errfmt.WrapError(err)
	}
	path := mountNSAbsolutePath

	// Maximum iterations to prevent infinite loops
	const maxSymlinkResolutions = 40
	seenPaths := make(map[string]struct{})

	for i := 0; i < maxSymlinkResolutions; i++ {
		absPath := filepath.Join(nsRootPath, path)

		// Security check: ensure we're still within the mount namespace
		if !cPathRes.isWithinMountNS(absPath, nsRootPath) {
			return "", errfmt.Errorf("symlink resolution escaped mount namespace boundary: %s", path)
		}

		// Use Lstat so that if absPath is a symlink, we don't follow it automatically
		info, err := os.Lstat(absPath)
		if err != nil {
			return "", errfmt.Errorf("failed to stat %s in mount NS %d: %v", path, mountNS, err)
		}

		// If not a symlink, resolution is complete
		if info.Mode()&os.ModeSymlink == 0 {
			// Cache the result (if cache is available)
			if cPathRes.symlinkCache != nil {
				cPathRes.symlinkCache.Add(cacheKey, path)
			}
			return path, nil
		}

		// Check for symlink loop
		if _, seen := seenPaths[path]; seen {
			return "", errfmt.Errorf("symlink loop detected at %s in mount NS %d", mountNSAbsolutePath, mountNS)
		}
		seenPaths[path] = struct{}{}

		linkTarget, err := os.Readlink(absPath)
		if err != nil {
			return "", errfmt.Errorf("failed to read symlink %s in mount NS %d: %v", path, mountNS, err)
		}

		if filepath.IsAbs(linkTarget) {
			path = linkTarget
		} else {
			// For relative targets, join with the directory of the current symlink
			dir := filepath.Dir(path)
			path = filepath.Join(dir, linkTarget)
		}

		path = filepath.Clean(path)
	}

	return "", errfmt.Errorf("too many symlink resolutions (>%d) at %s in mount NS %d, possible loop", maxSymlinkResolutions, mountNSAbsolutePath, mountNS)
}

// isWithinMountNS checks if the given path is within the mount namespace boundary
func (cPathRes *ContainerPathResolver) isWithinMountNS(absPath, nsRootPath string) bool {
	cleanPath := filepath.Clean(absPath)
	cleanRoot := filepath.Clean(nsRootPath)

	// Ensure the path starts with the namespace root
	return strings.HasPrefix(cleanPath, cleanRoot) &&
		(len(cleanPath) == len(cleanRoot) || cleanPath[len(cleanRoot)] == '/')
}

// ResolveAllLinks resolves all symlinks in a path component by component.
// This method processes each path component individually, resolving any symlinks
// encountered at each level. This provides comprehensive symlink resolution for
// the entire path.
//
// Parameters:
//   - mountNSAbsolutePath: absolute path within the mount namespace
//   - mountNS: mount namespace ID
//
// Returns the fully resolved path with all symlinks resolved.
func (cPathRes *ContainerPathResolver) ResolveAllLinks(mountNSAbsolutePath string, mountNS uint32) (
	string, error,
) {
	// Validate inputs
	if mountNSAbsolutePath == "" || mountNSAbsolutePath[0] != '/' {
		return "", ErrNonAbsolutePath
	}
	if mountNS == 0 {
		return "", errfmt.Errorf("invalid mount namespace ID: %d", mountNS)
	}

	path := filepath.ToSlash(mountNSAbsolutePath)
	components := strings.Split(path, "/")
	resolved := "/"

	for i, component := range components {
		if component == "" {
			continue
		}
		resolved = filepath.Join(resolved, component)
		newPath, err := cPathRes.ResolveLink(resolved, mountNS)
		if err != nil {
			return "", errfmt.Errorf("failed to resolve component %d (%s) in path %s: %v", i, component, mountNSAbsolutePath, err)
		}
		resolved = newPath
	}

	return resolved, nil
}

// GetProcMounts returns the path of a /proc/<pid>/mounts file for any process in the given mount namespace.
// It first tries to use cached PIDs for the namespace, and falls back to searching procfs.
//
// Parameters:
//   - mountNS: mount namespace ID
//
// Returns the path to a valid /proc/<pid>/mounts file for the namespace.
func (cPathRes *ContainerPathResolver) GetProcMounts(mountNS uint32) (string, error) {
	// Validate input
	if mountNS == 0 {
		return "", errfmt.Errorf("invalid mount namespace ID: %d", mountNS)
	}

	// Try using cached PIDs in this mount NS
	pids := cPathRes.mountNSPIDsCache.GetBucket(mountNS)
	for _, pid := range pids {
		path := fmt.Sprintf("/proc/%d/mounts", pid)
		if cPathRes.isFileAccessible(path) {
			return path, nil
		}
	}

	// No PIDs registered in this namespace, or couldn't access mounts file of any of the PIDs found.
	// Try finding one in procfs.
	pid, err := proc.GetAnyProcessInNS("mnt", mountNS)
	if err != nil {
		// Couldn't find a process in this namespace using procfs
		return "", errfmt.Errorf("could not find any process in mount namespace %d: %v", mountNS, err)
	}

	path := fmt.Sprintf("/proc/%d/mounts", pid)
	if !cPathRes.isFileAccessible(path) {
		return "", errfmt.Errorf("mounts file %s is not accessible", path)
	}

	// Register this process in the mount namespace cache for future use
	cPathRes.mountNSPIDsCache.AddBucketItem(mountNS, uint32(pid))

	return path, nil
}

// isFileAccessible checks if a file can be opened and read
func (cPathRes *ContainerPathResolver) isFileAccessible(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			logger.Debugw("Failed to close file", "path", path, "error", closeErr)
		}
	}()
	return true
}

var (
	ErrContainerFSUnreachable = errors.New("container file system is unreachable in mount namespace because there are not living children")
	ErrNonAbsolutePath        = errors.New("file path is not absolute in its container mount point")
)
