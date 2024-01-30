package mount

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/exp/slices"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// Constants

const (
	procMounts      = "/proc/self/mountinfo"
	procFilesystems = "/proc/filesystems"
	tmpPathPrefix   = "tracee"
)

//
// MountHostOnce
//

// MountHostOnce will make sure a given source and filesystem type are mounted just
// once: it will check if given source and fs type are already mounted, and given
// from the host filesystem, and if not, it will mount it (in a temporary directory)
// and manage it (umounting at its destruction). If already mounted, the filesystem
// is left untouched at object's destruction.
type MountHostOnce struct {
	source  string
	target  string
	fsType  string
	data    string
	managed bool
	mounted bool
}

func NewMountHostOnce(source, fstype, data, where string) (*MountHostOnce, error) {
	m := &MountHostOnce{
		source: source, // device and/or pseudo-filesystem to mount
		fsType: fstype, // fs type
		data:   data,   // extra data
	}

	// already mounted filesystems will be like mounted ones, but un-managed
	alreadyMounted, err := m.isMountedByOS(where)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	if !alreadyMounted {
		err = m.Mount()
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		m.managed = true // managed by this object
	}

	m.mounted = true
	logger.Debugw("created mount object", "managed", m.managed, "source", m.source, "target", m.target, "fsType", m.fsType, "data", m.data)

	return m, nil
}

func (m *MountHostOnce) Mount() error {
	path, err := os.MkdirTemp(os.TempDir(), tmpPathPrefix) // create temp dir
	if err != nil {
		return errfmt.WrapError(err)
	}
	mp, err := filepath.Abs(path) // pick mountpoint path
	if err != nil {
		return errfmt.WrapError(err)
	}

	m.target = mp

	// mount the filesystem to the target dir

	err = capabilities.GetInstance().Specific(
		func() error {
			return syscall.Mount(m.fsType, m.target, m.fsType, 0, m.data)
		},
		cap.SYS_ADMIN,
	)
	if err != nil {
		// remove created target directory on errors
		empty, _ := utils.IsDirEmpty(m.target)
		if empty {
			errRA := os.RemoveAll(m.target) // best effort for cleanup
			if errRA != nil {
				logger.Errorw("Removing all", "error", errRA)
			}
		}
	}

	return errfmt.WrapError(err)
}

func (m *MountHostOnce) Umount() error {
	if m.managed && m.mounted {
		// umount the filesystem from the target dir

		err := capabilities.GetInstance().Specific(
			func() error {
				return syscall.Unmount(m.target, 0)
			},
			cap.SYS_ADMIN,
		)
		if err != nil {
			return errfmt.WrapError(err)
		}

		m.mounted = false
		m.managed = false

		// check if target dir is empty before removing it
		empty, err := utils.IsDirEmpty(m.target)
		if err != nil {
			return errfmt.WrapError(err)
		}
		if !empty {
			return UnmountedDirNotEmpty(m.target)
		}

		// remove target dir (cleanup)
		return os.RemoveAll(m.target)
	}

	return nil
}

func (m *MountHostOnce) IsMounted() bool {
	return m.mounted
}

func (m *MountHostOnce) GetMountpoint() string {
	return m.target
}

// private

func (m *MountHostOnce) isMountedByOS(where string) (bool, error) {
	mp, err := SearchMountpointFromHost(m.fsType, m.data)
	if err != nil || mp == "" {
		return false, errfmt.WrapError(err)
	}
	if where != "" && !strings.Contains(mp, where) {
		return false, nil
	}

	m.target = mp // replace given target dir with existing mountpoint
	m.mounted = true
	m.managed = false // proforma

	return true, nil
}

//
// General
//

// IsFileSystemSupported checks if given fs is supported by the running kernel
func IsFileSystemSupported(fsType string) (bool, error) {
	file, err := os.Open(procFilesystems)
	if err != nil {
		return false, CouldNotOpenFile(procFilesystems, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		last := line[len(line)-1]
		if last == fsType {
			return true, nil
		}
	}

	return false, nil
}

// SearchMountpointFromHost returns the last mountpoint for a given filesystem type
// containing a searchable string. It confirms the mount originates from the root file
// system.
func SearchMountpointFromHost(fstype string, search string) (string, error) {
	mp := ""

	file, err := os.Open(procMounts)
	if err != nil {
		return "", errfmt.WrapError(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		mountRoot := line[3]
		mountpoint := line[4]
		sepIndex := slices.Index(line, "-")
		fsTypeIndex := sepIndex + 1
		currFstype := line[fsTypeIndex]
		// Check for the following 3 conditions:
		// 1. The fs type is the one we search for
		// 2. The mountpoint contains the path we are searching
		// 3. The root path in the mounted filesystem is that of the host.
		//	  This means, that the root of the mounted filesystem is /.
		//    For example, if we are searching for /sys/fs/cgroup, we want to
		//    be sure that it is not actually .../sys/fs/cgroup, but strictly
		//    the searched path.
		if fstype == currFstype && strings.Contains(mountpoint, search) && mountRoot == "/" {
			mp = mountpoint
			break
		}
	}

	return mp, nil
}
