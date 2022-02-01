package containers

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
)

// Containers contains information about running containers in the host.
type Containers struct {
	cgroupV1 bool
	cgroupMP string
	cgroups  map[uint32]CgroupInfo
	deleted  []uint64
	mtx      sync.RWMutex // protecting both cgroups and deleted fields
}

// CgroupInfo represents a cgroup dir (might describe a container cgroup dir).
type CgroupInfo struct {
	Path        string
	ContainerId string
	Runtime     string
	Ctime       time.Time
	expiresAt   time.Time
}

// InitContainers initializes a Containers object and returns a pointer to it.
// User should further call "Populate" and iterate with Containers data.
func InitContainers() *Containers {
	cgroupV1 := false
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); os.IsNotExist(err) {
		cgroupV1 = true
	}

	return &Containers{
		cgroupV1: cgroupV1,
		cgroupMP: "",
		cgroups:  make(map[uint32]CgroupInfo),
		mtx:      sync.RWMutex{},
	}
}

func (c *Containers) IsCgroupV1() bool {
	return c.cgroupV1
}

// Populate populates Containers struct by reading mounted proc and cgroups fs.
func (c *Containers) Populate() error {
	err := c.procMountsCgroups()
	if err != nil {
		return err
	}

	return c.populate()
}

// procMountsCgroups finds cgroups v1 and v2 mountpoints.
func (c *Containers) procMountsCgroups() error {
	mountsFile := "/proc/mounts"
	file, err := os.Open(mountsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Split(scanner.Text(), " ")
		mountpoint := sline[1]
		fstype := sline[2]
		if c.cgroupV1 {
			if fstype == "cgroup" && strings.Contains(mountpoint, "cpuset") {
				c.cgroupMP = mountpoint
			}
		} else if fstype == "cgroup2" {
			c.cgroupMP = mountpoint
		}
	}

	return nil
}

// gets a containerID from a given task or process directory path
func GetContainerIdFromTaskDir(taskPath string) (string, error) {
	containerId := ""
	taskPath = fmt.Sprintf("%s/cgroup", taskPath)
	cgroupFile, err := os.Open(taskPath)
	if err != nil {
		return containerId, err
	}
	defer cgroupFile.Close()
	scanner := bufio.NewScanner(cgroupFile)
	for scanner.Scan() {
		containerId, _ := getContainerIdFromCgroup(scanner.Text())
		if containerId != "" {
			break
		}
	}
	return containerId, nil
}

// populate walks the cgroup fs informing CgroupUpdate() about existing dirs.
func (c *Containers) populate() error {
	if c.cgroupMP == "" {
		return fmt.Errorf("could not determine cgroup mount point")
	}

	fn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		if !d.IsDir() {
			return nil
		}

		// cgroup id == container cgroupfs directory inode (lower 32 bits)
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			return nil
		}

		inodeNumber := stat.Ino
		statusChange := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
		_, err = c.CgroupUpdate(inodeNumber, path, statusChange)

		return err
	}

	return filepath.WalkDir(c.cgroupMP, fn)
}

// CgroupUpdate checks if given path belongs to a known container runtime,
// saving container information in Containers CgroupInfo map.
// NOTE: ALL given cgroup dir paths are stored in CgroupInfo map.
func (c *Containers) CgroupUpdate(cgroupId uint64, path string, ctime time.Time) (CgroupInfo, error) {
	containerId, runtime := getContainerIdFromCgroup(path)

	info := CgroupInfo{
		Path:        path,
		ContainerId: containerId,
		Runtime:     runtime,
		Ctime:       ctime,
	}

	c.mtx.Lock()
	c.cgroups[uint32(cgroupId)] = info
	c.mtx.Unlock()

	return info, nil
}

var (
	containerIdFromCgroupRegex = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
)

// getContainerIdFromCgroup extracts container id and its runtime from path.
// It returns (containerId, runtime string).
func getContainerIdFromCgroup(cgroupPath string) (string, string) {
	prevPathComp := ""
	for _, pc := range strings.Split(cgroupPath, "/") {
		if len(pc) < 64 {
			prevPathComp = pc
			continue
		}

		runtime := "unknown"
		id := strings.TrimSuffix(pc, ".scope")

		switch {
		case strings.HasPrefix(id, "docker-"):
			runtime = "docker"
			id = strings.TrimPrefix(id, "docker-")
		case strings.HasPrefix(id, "crio-"):
			runtime = "crio"
			id = strings.TrimPrefix(id, "crio-")
		case strings.HasPrefix(id, "cri-containerd-"):
			runtime = "containerd"
			id = strings.TrimPrefix(id, "cri-containerd-")
		case strings.HasPrefix(id, "libpod-"):
			runtime = "podman"
			id = strings.TrimPrefix(id, "libpod-")
		}

		regex := containerIdFromCgroupRegex
		if matched := regex.MatchString(id); matched {
			if runtime == "unknown" && prevPathComp == "docker" {
				// non-systemd docker with format: .../docker/01adbf...f26db7f/
				runtime = "docker"
			}

			// return first match: closest to root dir path component
			// (to have container id of the outer container)
			return id, runtime
		}

		prevPathComp = pc
	}

	// cgroup dirs unrelated to containers provides empty (containerId, runtime)
	return "", ""
}

// CgroupRemove removes cgroupInfo of deleted cgroup dir from Containers struct.
// NOTE: Expiration logic of 5 seconds to avoid race conditions (if cgroup dir
// event arrives too fast and its cgroupInfo data is still needed).
func (c *Containers) CgroupRemove(cgroupId uint64) {
	now := time.Now()
	var deleted []uint64
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// process previously deleted cgroupInfo data (deleted cgroup dirs)
	for _, id := range c.deleted {
		info := c.cgroups[uint32(id)]
		if now.After(info.expiresAt) {
			delete(c.cgroups, uint32(id))
		} else {
			deleted = append(deleted, id)
		}
	}
	c.deleted = deleted

	info := c.cgroups[uint32(cgroupId)]
	info.expiresAt = now.Add(5 * time.Second)
	c.cgroups[uint32(cgroupId)] = info
	c.deleted = append(c.deleted, cgroupId)
}

// CgroupMkdir adds cgroupInfo of a created cgroup dir to Containers struct.
func (c *Containers) CgroupMkdir(cgroupId uint64, subPath string) (CgroupInfo, error) {
	// Find container cgroup dir path to get directory stats
	curTime := time.Now()
	path, err := getCgroupPath(c.cgroupMP, cgroupId, subPath)
	if err == nil {
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err == nil {
			// Add cgroupInfo to Containers struct w/ found path (and its last modification time)
			return c.CgroupUpdate(cgroupId, path, time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec))
		}
	}

	// No entry found: container may have already exited.
	// Add cgroupInfo to Containers struct with existing data.
	// In this case, ctime is just an estimation (current time).
	return c.CgroupUpdate(cgroupId, subPath, curTime)
}

// getCgroupPath walks the cgroup fs and provides the cgroup directory path of
// given cgroupId and subPath (related to cgroup fs root dir). If subPath is
// empty, then all directories from cgroup fs will be searched for the given
// cgroupId.
func getCgroupPath(rootDir string, cgroupId uint64, subPath string) (string, error) {
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
		path, err := getCgroupPath(entryPath, cgroupId, subPath)
		if err == nil {
			return path, nil
		}
	}

	return "", fs.ErrNotExist
}

// FindContainerCgroupID32LSB returns the 32 LSB of the Cgroup ID for a given container ID
func (c *Containers) FindContainerCgroupID32LSB(containerID string) []uint32 {
	var cgroupIDs []uint32
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	for k, v := range c.cgroups {
		if strings.HasPrefix(v.ContainerId, containerID) {
			cgroupIDs = append(cgroupIDs, k)
		}
	}
	return cgroupIDs
}

// GetCgroupInfo returns the Containers struct cgroupInfo data of a given cgroupId.
func (c *Containers) GetCgroupInfo(cgroupId uint64) CgroupInfo {
	if !c.CgroupExists(cgroupId) {
		// There should be a cgroupInfo for the given cgroupId but there isn't.
		// Tracee might be processing an event for an already created container
		// before the CgroupMkdirEventID logic was executed, for example.

		// Get the path for given cgroupId from cgroupfs and update its
		// cgroupInfo in the Containers struct. An empty subPath will make
		// getCgroupPath() to walk all cgroupfs directories until it finds the
		// directory of given cgroupId.
		path, err := getCgroupPath(c.cgroupMP, cgroupId, "")
		if err == nil {
			var stat syscall.Stat_t
			if err = syscall.Stat(path, &stat); err == nil {
				info, err := c.CgroupUpdate(cgroupId, path, time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec))
				if err == nil {
					return info
				}
			}
		}
	}

	c.mtx.RLock()
	cgroupInfo := c.cgroups[uint32(cgroupId)]
	c.mtx.RUnlock()

	return cgroupInfo
}

// CgroupExists checks if there is a cgroupInfo data of a given cgroupId.
func (c *Containers) CgroupExists(cgroupId uint64) bool {
	c.mtx.RLock()
	_, ok := c.cgroups[uint32(cgroupId)]
	c.mtx.RUnlock()
	return ok
}

const (
	containerExisted uint8 = iota + 1
	containerCreated
	containerStarted
)

func (c *Containers) PopulateBpfMap(bpfModule *libbpfgo.Module, mapName string) error {
	containersMap, err := bpfModule.GetMap(mapName)
	if err != nil {
		return err
	}

	c.mtx.RLock()
	for cgroupIdLsb, info := range c.cgroups {
		if info.ContainerId != "" {
			state := containerExisted
			err = containersMap.Update(unsafe.Pointer(&cgroupIdLsb), unsafe.Pointer(&state))
		}
	}
	c.mtx.RUnlock()

	return err
}

func RemoveFromBpfMap(bpfModule *libbpfgo.Module, cgroupId uint64, mapName string) error {
	containersMap, err := bpfModule.GetMap(mapName)
	if err != nil {
		return err
	}

	cgroupIdLsb := uint32(cgroupId)
	return containersMap.DeleteKey(unsafe.Pointer(&cgroupIdLsb))
}
