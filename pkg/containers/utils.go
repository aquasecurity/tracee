package containers

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// runsOnContainerV1 tests if process is running on a container in cgroupsv1
// it tests by checking for existance of a release_agent file in cpuset
// from https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt:
//
// - release_agent: ...	 (this file exists in the top cgroup only)
//
// WARNING: IF THIS WASN'T CLEAR THIS IS ONLY VALID FOR CGROUPSV1 MACHINES
func runsOnContainerV1() (bool, error) {
	const releseAgentPath = "/sys/fs/cgroup/cpuset/release_agent"
	_, err := os.Stat(releseAgentPath)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// mountsCpuset mounts cpuset cgroup controller to the container's current working directory
// this is done in order to detect host cgroup data when running tracee from a container in cgroupsv1
// since the function uses the mount syscall, it requires CAP_SYS_ADMIN
func mountCpuset(mountPath string) error {
	mp, _ := isMountpoint(mountPath, cgroupV1FsType)

	if mp {
		// already mounted
		return nil
	}

	// equivalent to mount -t cgroup -o cpuset cgroup mountPath
	// we ignore EBUSY because it means we already mounted the cpuset
	if err := syscall.Mount("cgroup", mountPath, "cgroup", 0, "cpuset"); err != nil && !errors.Is(err, syscall.EBUSY) {
		return fmt.Errorf("failed to mount %s", err)
	}
	return nil
}

// getCgroupV1HierarchyId returns the hierarchyId of cgroupsv1
func getCgroupV1HierarchyId() (int, error) {
	const cgroupsFile = "/proc/cgroups"
	file, err := os.Open(cgroupsFile)
	if err != nil {
		return -1, fmt.Errorf("could not open cgroups file %s: %w", cgroupsFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Fields(scanner.Text())
		if len(sline) < 2 || sline[0] != cgroupV1Controller {
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

// isMountpoint searches if path is a mountpoint for fstype
func isMountpoint(path string, fstype string) (bool, error) {
	mountsFile := "/proc/mounts"
	file, err := os.Open(mountsFile)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Split(scanner.Text(), " ")
		mountpoint := sline[1]
		currFstype := sline[2]

		if fstype == currFstype && mountpoint == path {
			return true, nil
		}
	}

	return false, nil
}

// searchMountpoint finds the last mountpoint for the given fstype which includes the search string
// if the search string is empty the function will return the last found path
func searchMountpoint(fstype string, search string) (string, error) {
	mountsFile := "/proc/mounts"
	file, err := os.Open(mountsFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	mp := ""
	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Split(scanner.Text(), " ")
		mountpoint := sline[1]
		currFstype := sline[2]

		if fstype == currFstype && strings.Contains(mountpoint, search) {
			mp = mountpoint
		}
	}
	return mp, nil
}
