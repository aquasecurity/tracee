package cgroup

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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
	mounted    *mount.MountOnce
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
	c.mounted, err = mount.NewMountOnce(
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
	mounted    *mount.MountOnce
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
	c.mounted, err = mount.NewMountOnce(
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

// GetCgroupPath walks the cgroup fs and provides the cgroup directory path of
// given cgroupId and subPath (related to cgroup fs root dir). If subPath is
// empty, then all directories from cgroup fs will be searched for the given
// cgroupId.
func GetCgroupPath(rootDir string, cgroupId uint64, subPath string) (string, error) {
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return "", errfmt.WrapError(err)
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
