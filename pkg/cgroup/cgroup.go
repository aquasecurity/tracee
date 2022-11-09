package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/mount"
)

const CgroupV1Controller = "cpuset"
const CgroupV1FsType = "cgroup"
const CgroupV2FsType = "cgroup2"

const CgroupCpusetReleaseAgent = "/sys/fs/cgroup/cpuset/release_agent"

// RunsOnContainerV1 tests if process is running on a container in cgroupsv1 it
// tests by checking for existance of a release_agent file in cpuset from
// https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt:
//
// - release_agent: ...	 (this file exists in the top cgroup only)
//
// WARNING: IF THIS WASN'T CLEAR THIS IS ONLY VALID FOR CGROUPSV1 MACHINES
func RunsOnContainerV1() (bool, error) {
	_, err := os.Stat(CgroupCpusetReleaseAgent)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// GetCgroupV1HierarchyId returns the hierarchyId of cgroupsv1
func GetCgroupV1HierarchyId() (int, error) {
	const cgroupsFile = "/proc/cgroups"
	file, err := os.Open(cgroupsFile)
	if err != nil {
		return -1, fmt.Errorf("could not open cgroups file %s: %w", cgroupsFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Fields(scanner.Text())
		if len(sline) < 2 || sline[0] != CgroupV1Controller {
			continue
		}
		intID, err := strconv.Atoi(sline[1])
		if err != nil || intID < 0 {
			return -1, fmt.Errorf("error parsing %s: %w", cgroupsFile, err)
		}
		return intID, nil
	}
	return -1, fmt.Errorf("couldn't determine cgroup v1 hierarchy id")
}

// MountCgroupV1Cpuset mounts cpuset cgroup controller to the container's
// current working directory this is done in order to detect host cgroup data
// when running tracee from a container in cgroupsv1 since the function uses the
// mount syscall, it requires CAP_SYS_ADMIN
func MountCgroupV1Cpuset(mountPath string) error {
	mp, _ := mount.IsMountpoint(mountPath, CgroupV1FsType)

	if mp {
		// already mounted
		return nil
	}

	// equivalent to mount -t cgroup -o cpuset cgroup mountPath
	// we ignore EBUSY because it means we already mounted the cpuset
	err := syscall.Mount("cgroup", mountPath, "cgroup", 0, "cpuset")
	if err != nil && !errors.Is(err, syscall.EBUSY) {
		return fmt.Errorf("failed to mount %s", err)
	}
	return nil
}

// GetCgroupPath walks the cgroup fs and provides the cgroup directory path of
// given cgroupId and subPath (related to cgroup fs root dir). If subPath is
// empty, then all directories from cgroup fs will be searched for the given
// cgroupId.
func GetCgroupPath(rootDir string, cgroupId uint64, subPath string) (string, error) {
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		entryPath := filepath.Join(rootDir, entry.Name())
		if strings.HasSuffix(entryPath, subPath) {
			// Lower 32 bits of the cgroup id == inode number of matching cgroupfs entry
			var stat syscall.Stat_t
			if err := syscall.Stat(entryPath, &stat); err == nil {
				// Check if this cgroup path belongs to cgroupId
				if (stat.Ino & 0xFFFFFFFF) == (cgroupId & 0xFFFFFFFF) {
					return entryPath, nil
				}
			}
		}

		// No match at this dir level: continue recursively
		path, err := GetCgroupPath(entryPath, cgroupId, subPath)
		if err == nil {
			return path, nil
		}
	}

	return "", fs.ErrNotExist
}
