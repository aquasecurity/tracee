package mount

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

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
	mpInode int
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

		// Try to get the inode number of the current mountpoint.
		var stat syscall.Stat_t
		if err := syscall.Stat(m.target, &stat); err != nil {
			logger.Warnw("Stat failed", "mountpoint", m.target, "error", err)
		} else {
			m.mpInode = int(stat.Ino)
		}
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

func (m *MountHostOnce) GetMountpointInode() int {
	return m.mpInode
}

// private

func (m *MountHostOnce) isMountedByOS(where string) (bool, error) {
	mp, inode, err := SearchMountpointFromHost(m.fsType, m.data)
	if err != nil || mp == "" {
		return false, errfmt.WrapError(err)
	}
	if where != "" && !strings.Contains(mp, where) {
		return false, nil
	}

	m.target = mp // replace given target dir with existing mountpoint
	m.mpInode = inode
	m.mounted = true
	m.managed = false

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

// SearchMountpointFromHost scans the /proc/self/mountinfo file to find the oldest
// mountpoint of a specified filesystem type (fstype) that contains a given
// searchable string (search) in its path. This is useful in environments like
// containers where multiple mountpoints may exist, and we need to find the one
// that belongs to the host namespace.
//
// Parameters:
// - fstype: The filesystem type to search for (e.g., "cgroup2", "ext4").
// - search: The substring to search for within the mountpoint path (e.g., "/sys/fs/cgroup").
//
// Returns:
// - string: The path of the oldest matching mountpoint.
// - int: The inode number of the matching mountpoint.
// - error: Any error encountered while reading the /proc/mounts file.
func SearchMountpointFromHost(fstype string, search string) (string, int, error) {
	const mountRootIndex = 3
	const mountpointIndex = 4

	mp := ""   // matched mountpoint search var
	inode := 0 // matched mountpoint's inode

	file, err := os.Open(procMounts)
	if err != nil {
		return "", 0, errfmt.WrapError(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")

		// fstype field is located right after "-"
		// before - there are optional fields, which makes the location of
		// the fstype field indeterminate
		sepIndex := slices.Index(line, "-")
		fsTypeIndex := sepIndex + 1

		root := line[mountRootIndex]        // current search mountpoint root
		mountpoint := line[mountpointIndex] // current search mountpoint path
		currFstype := line[fsTypeIndex]     // current search mountpoint fs type

		// First check for the following 3 conditions:
		// 1. The fs type is the one we search for
		// 2. The mountpoint contains the path we are searching
		// 3. The root path in the mounted filesystem is that of the host.
		//	  This means, that the root of the mounted filesystem is /.
		//    For example, if we are searching for a mountpoint with cpuset we want
		//    to be sure that it is not actually <some_other_dir>/.../.../...cpuset,
		//    but strictly originating in the root fs.
		// 	  EXAMPLE: EKS and TAS mount their cgroup controllers ontop of their pod
		//             cgroup folder root:
		//             /kubepods.slice/.../cri-containerd-abcdef123.scope -> /sys/fs/cgroup/cpuset
		//			   /garden/fc6c9886-cd3d-4d87-5053-c102 -> /sys/fs/cgroup/cpuset
		//    Without strictly requiring the root path the resulting search path for cgroup path results in searching:
		//    /kubepods.slice/.../cri-containerd-abcdef123.scope/sys/fs/cgroup/cpuset/kubepods.slice/.../cri-containerd-somecontainerid123
		//    which doesn't exist.
		if fstype == currFstype && strings.Contains(mountpoint, search) && root == "/" {
			// Try to get the inode number of the current mountpoint.
			var stat syscall.Stat_t
			if err := syscall.Stat(mountpoint, &stat); err != nil {
				logger.Warnw("Stat failed", "mountpoint", mountpoint, "error", err)
				continue // Skip this mountpoint if stat fails
			}
			currInode := int(stat.Ino)

			// Update the result if either apply:
			// 1. this is the first match
			// 2. the current mountpoint inode is lower than the currently matching mountpoint
			// 2. the current mountpoint shares an inode but its root has a shorter path
			if inode == 0 || currInode < inode ||
				(currInode == inode && len(mp) < len(mountpoint)) {
				mp = mountpoint
				inode = currInode
			}
		}
	}

	return mp, inode, nil
}
