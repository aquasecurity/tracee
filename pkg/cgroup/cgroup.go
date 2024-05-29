package cgroup

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/mount"
)

// Constants

const (
	CgroupV1FsType          = "cgroup"
	CgroupV2FsType          = "cgroup2"
	CgroupDefaultController = "cpuset"
	CgroupControllersFile   = "/sys/fs/cgroup/cgroup.controllers"
	procCgroups             = "/proc/cgroups"
	sysFsCgroup             = "/sys/fs/cgroup"
)

// Versions

type CgroupVersion int

func (v CgroupVersion) String() string {
	switch v {
	case CgroupVersion1:
		return CgroupV1FsType
	case CgroupVersion2:
		return CgroupV2FsType
	}

	return ""
}

const (
	CgroupVersion1 CgroupVersion = iota
	CgroupVersion2
)

//
// Cgroups
//

type Cgroups struct {
	cgroupv1 Cgroup
	cgroupv2 Cgroup
	cgroup   *Cgroup // pointer to default cgroup version
	hid      int     // default cgroup controller hierarchy ID
}

func NewCgroups() (*Cgroups, error) {
	var err error
	var cgrp *Cgroup
	var cgroupv1, cgroupv2 Cgroup

	// discover the default cgroup being used
	defaultVersion, err := GetCgroupDefaultVersion()
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	// only start cgroupv1 if it is the OS default (or else it isn't needed)
	if defaultVersion == CgroupVersion1 {
		cgroupv1, err = NewCgroup(CgroupVersion1)
		if err != nil {
			if _, ok := err.(*VersionNotSupported); !ok {
				return nil, errfmt.WrapError(err)
			}
		}
	}

	// start cgroupv2 (if supported)
	cgroupv2, err = NewCgroup(CgroupVersion2)
	if err != nil {
		if _, ok := err.(*VersionNotSupported); !ok {
			return nil, errfmt.WrapError(err)
		}
	}

	// at least one (or both) has to be supported
	if cgroupv1 == nil && cgroupv2 == nil {
		return nil, NoCgroupSupport()
	}

	hid := 0

	// adjust pointer to the default cgroup version
	switch defaultVersion {
	case CgroupVersion1:
		if cgroupv1 == nil {
			return nil, CouldNotFindOrMountDefaultCgroup(CgroupVersion1)
		}
		cgrp = &cgroupv1

		// discover default cgroup controller hierarchy id for cgroupv1
		hid, err = GetCgroupControllerHierarchy(CgroupDefaultController)
		if err != nil {
			return nil, errfmt.WrapError(err)
		}

	case CgroupVersion2:
		if cgroupv2 == nil {
			return nil, CouldNotFindOrMountDefaultCgroup(CgroupVersion2)
		}
		cgrp = &cgroupv2
	}

	cs := &Cgroups{
		cgroupv1: cgroupv1,
		cgroupv2: cgroupv2,
		cgroup:   cgrp,
		hid:      hid,
	}

	return cs, nil
}

func (cs *Cgroups) Destroy() error {
	if cs.cgroupv1 != nil {
		err := cs.cgroupv1.destroy()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}
	if cs.cgroupv2 != nil {
		return cs.cgroupv2.destroy()
	}

	return nil
}

func (cs *Cgroups) GetDefaultCgroupHierarchyID() int {
	return cs.hid
}

func (cs *Cgroups) GetDefaultCgroup() Cgroup {
	return *cs.cgroup
}

func (cs *Cgroups) GetCgroup(ver CgroupVersion) Cgroup {
	switch ver {
	case CgroupVersion1:
		return cs.cgroupv1
	case CgroupVersion2:
		return cs.cgroupv2
	}

	return nil
}

//
// Cgroup
//

type Cgroup interface {
	init() error
	destroy() error
	GetMountPoint() string
	getDefaultHierarchyID() int
	GetVersion() CgroupVersion
}

func NewCgroup(ver CgroupVersion) (Cgroup, error) {
	var c Cgroup

	switch ver {
	case CgroupVersion1:
		c = &CgroupV1{}
	case CgroupVersion2:
		c = &CgroupV2{}
	}

	return c, c.init()
}

// cgroupv1

type CgroupV1 struct {
	mounted    *mount.MountHostOnce
	mountpoint string
	hid        int
}

func (c *CgroupV1) init() error {
	// 0. check if cgroup type is supported
	supported, err := mount.IsFileSystemSupported(CgroupVersion1.String())
	if err != nil {
		return errfmt.WrapError(err)
	}
	if !supported {
		return &VersionNotSupported{}
	}

	// 1. mount cgroup (if needed)
	c.mounted, err = mount.NewMountHostOnce(
		CgroupV1FsType,
		CgroupV1FsType,
		CgroupDefaultController,
		sysFsCgroup, // where to check for already mounted cgroupfs
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// 2. discover where cgroup is mounted
	c.mountpoint = c.mounted.GetMountpoint()

	inode := c.mounted.GetMountpointInode()
	if inode != 1 {
		logger.Warnw("Cgroup mountpoint is not in the host cgroup namespace", "mountpoint", c.mountpoint, "inode", inode)
	}

	return nil
}

func (c *CgroupV1) destroy() error {
	return c.mounted.Umount()
}

func (c *CgroupV1) GetMountPoint() string {
	return c.mountpoint
}

func (c *CgroupV1) getDefaultHierarchyID() int {
	return c.hid
}

func (c *CgroupV1) GetVersion() CgroupVersion {
	return CgroupVersion1
}

// cgroupv2

type CgroupV2 struct {
	mounted    *mount.MountHostOnce
	mountpoint string
	hid        int
}

func (c *CgroupV2) init() error {
	// 0. check if cgroup type is supported
	supported, err := mount.IsFileSystemSupported(CgroupVersion2.String())
	if err != nil {
		return errfmt.WrapError(err)
	}
	if !supported {
		return &VersionNotSupported{}
	}

	// 1. mount cgroup (if needed)
	c.mounted, err = mount.NewMountHostOnce(
		CgroupV2FsType,
		CgroupV2FsType,
		"",          // cgroupv2 has no default controller
		sysFsCgroup, // where to check for already mounted cgroupfs
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// 2. discover where cgroup is mounted
	c.mountpoint = c.mounted.GetMountpoint()

	inode := c.mounted.GetMountpointInode()
	if inode != 1 {
		logger.Warnw("Cgroup mountpoint is not in the host cgroup namespace", "mountpoint", c.mountpoint, "inode", inode)
	}

	return nil
}

func (c *CgroupV2) destroy() error {
	return c.mounted.Umount()
}

func (c *CgroupV2) GetMountPoint() string {
	return c.mountpoint
}

func (c *CgroupV2) getDefaultHierarchyID() int {
	return c.hid
}

func (c *CgroupV2) GetVersion() CgroupVersion {
	return CgroupVersion2
}

//
// General
//

func GetCgroupDefaultVersion() (CgroupVersion, error) {
	// 1st Method: already mounted cgroupv1 filesystem

	if ok, _ := IsCgroupV2MountedAndDefault(); ok {
		return CgroupVersion2, nil
	}

	//
	// 2nd Method: From cgroup man page:
	// ...
	// 2. The unique ID of the cgroup hierarchy on which this
	//    controller is mounted. If multiple cgroups v1
	//    controllers are bound to the same hierarchy, then each
	//    will show the same hierarchy ID in this field.  The
	//    value in this field will be 0 if:
	//
	//    a) the controller is not mounted on a cgroups v1
	//       hierarchy;
	//    b) the controller is bound to the cgroups v2 single
	//       unified hierarchy; or
	//    c) the controller is disabled (see below).
	// ...

	var value int

	file, err := os.Open(procCgroups)
	if err != nil {
		return -1, CouldNotOpenFile(procCgroups, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if line[0] != CgroupDefaultController {
			continue
		}
		value, err = strconv.Atoi(line[1])
		if err != nil || value < 0 {
			return -1, ErrorParsingFile(procCgroups, err)
		}
	}

	if value == 0 { // == (a), (b) or (c)
		return CgroupVersion2, nil
	}

	return CgroupVersion1, nil
}

// IsCgroupV2MountedAndDefault tests if cgroup2 is mounted and is the default
// cgroup version being used by the running environment. It does so by checking
// the existence of a "cgroup.controllers" file in default cgroupfs mountpoint.
func IsCgroupV2MountedAndDefault() (bool, error) {
	_, err := os.Stat(CgroupControllersFile)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, CouldNotOpenFile(CgroupControllersFile, err)
	}

	return true, nil
}

// Returns a cgroup controller hierarchy value
func GetCgroupControllerHierarchy(subsys string) (int, error) {
	var value int

	file, err := os.Open(procCgroups)
	if err != nil {
		return -1, CouldNotOpenFile(procCgroups, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 2 || line[0] != subsys {
			continue
		}
		value, err = strconv.Atoi(line[1])
		if err != nil || value < 0 {
			return -1, ErrorParsingFile(procCgroups, err)
		}
	}

	return value, nil
}

// GetCgroupPath iteratively searches the cgroup filesystem for the directory
// that matches the given cgroupId and optional subPath. If subPath is empty,
// all directories within the cgroup filesystem are searched.
//
// Parameters:
// - rootDir: The root directory of the cgroup filesystem.
// - cgroupId: The cgroup ID to search for.
// - subPath: An optional subpath to narrow the search.
//
// Returns:
// - The path of the found cgroup directory.
// - The creation time (ctime) of the found cgroup directory.
// - An error if the directory could not be found or an I/O error occurred.
//
// Note: For cgroupfs, the inode number of a cgroupfs entry matches the cgroup ID.
// This function leverages this fact by checking if the lower 32 bits of the cgroup ID
// match the inode number of the entry to identify the desired cgroup directory.
func GetCgroupPath(rootDir string, cgroupId uint64, subPath string) (string, time.Time, error) {
	// Stack to hold directories to explore
	stack := []string{rootDir}

	for len(stack) > 0 {
		// Pop the last directory from the stack
		currentDir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// Read directory entries
		entries, err := os.ReadDir(currentDir)
		if err != nil {
			return "", time.Time{}, errfmt.WrapError(err)
		}

		for _, entry := range entries {
			// Skip non-directory entries
			if !entry.IsDir() {
				continue
			}

			entryPath := filepath.Join(currentDir, entry.Name())

			// Check if the entry matches the subPath (if provided)
			if strings.HasSuffix(entryPath, subPath) {
				// Retrieve inode information
				var stat syscall.Stat_t
				if err := syscall.Stat(entryPath, &stat); err == nil {
					// Check if the lower 32 bits of the cgroupId match the inode number
					if (stat.Ino & 0xFFFFFFFF) == (cgroupId & 0xFFFFFFFF) {
						ctime := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
						return entryPath, ctime, nil
					}
				}
			}

			// Push the directory to the stack for further exploration
			stack = append(stack, entryPath)
		}
	}

	return "", time.Time{}, fs.ErrNotExist
}
