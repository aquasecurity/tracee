package containers

import (
	"bufio"
	"errors"
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

// Containers contain information about running containers in the host.
type Containers struct {
	cgroupV1 bool
	cgroupMP string
	cgroups  map[uint32]CgroupInfo
	deleted  []uint64
	mtx      sync.RWMutex // protecting both cgroups and deleted fields
}

type CgroupInfo struct {
	Path        string
	ContainerId string
	Runtime     string
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

// Populate will populate all Containers information by reading mounted proc
// and cgroups filesystems.
func (c *Containers) Populate() error {
	// do all the hard work

	err := c.procMountsCgroups()
	if err != nil {
		return err
	}

	return c.populate()
}

// procMountsCgroups finds cgroups v1 and v2 mountpoints for the procfs walks.
func (c *Containers) procMountsCgroups() error {
	// find cgroups v1 and v2 mountpoints for procfs walks

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

// populate walks through cgroups (v1 & v2) filesystems and
// finds directories based on known container runtimes patterns.
// it then extracts containers information and saves it by their uuid
func (c *Containers) populate() error {
	fn := func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			return nil
		}

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		// The lower 32 bits of the cgroup id are the inode number of the matching cgroupfs entry
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			return nil
		}

		_, err = c.CgroupUpdate(stat.Ino, path)
		return err
	}

	if c.cgroupMP == "" {
		return fmt.Errorf("could not determine cgroup mount point")
	}

	return filepath.WalkDir(c.cgroupMP, fn)
}

func (c *Containers) cgroupLookupUpdate(cgroupId uint64) error {
	fn := func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			return nil
		}

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		// The lower 32 bits of the cgroup id are the inode number of the matching cgroupfs entry
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			return nil
		}

		// Check if this cgroup path belongs to cgroupId
		if (stat.Ino & 0xFFFFFFFF) != (cgroupId & 0xFFFFFFFF) {
			return nil
		}

		// If we reached this point, we found a match for cgroupId - update cgroups map and break search
		c.CgroupUpdate(cgroupId, path)
		return fs.ErrExist
	}

	err := filepath.WalkDir(c.cgroupMP, fn)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err == nil {
		// No match was found - update cgroup id with an empty entry
		c.mtx.Lock()
		c.cgroups[uint32(cgroupId)] = CgroupInfo{}
		c.mtx.Unlock()
	}
	return err
}

// check if path belongs to a known container runtime and
// add cgroupId with a matching container id, extracted from path
func (c *Containers) CgroupUpdate(cgroupId uint64, path string) (CgroupInfo, error) {
	info := CgroupInfo{Path: path}
	info.ContainerId, info.Runtime = getContainerIdFromCgroup(path)

	c.mtx.Lock()
	c.cgroups[uint32(cgroupId)] = info
	c.mtx.Unlock()
	return info, nil
}

// extract container id and container runtime from path
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

		if matched, _ := regexp.MatchString(`^[A-Fa-f0-9]{64}$`, id); matched {
			if runtime == "unknown" && prevPathComp == "docker" {
				// non-systemd docker in the following format:
				// /docker/01adbaf26db7fac62f8b7ec5b116b2e60f4abbf230e29122e667996c6b5c04d4/
				runtime = "docker"
			}
			// return first match as we want to get container info with respect to host
			return id, runtime
		}
		prevPathComp = pc
	}

	return "", ""
}

func (c *Containers) CgroupRemove(cgroupId uint64) {
	now := time.Now()
	// prune containers that have been removed more than 5 seconds ago
	var deleted []uint64
	c.mtx.Lock()
	defer c.mtx.Unlock()
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
	// keep track of removed containers for a short period
	c.deleted = append(c.deleted, cgroupId)
}

// GetContainers provides a list of all added containers by their uuid.
func (c *Containers) GetContainers() []string {
	var conts []string
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	for _, v := range c.cgroups {
		if v.ContainerId != "" && v.expiresAt.IsZero() {
			conts = append(conts, v.ContainerId)
		}
	}
	return conts
}

func (c *Containers) GetCgroupInfo(cgroupId uint64) CgroupInfo {
	if !c.CgroupExists(cgroupId) {
		// Handle false container negatives (we should have identified this container id, but we didn't)
		// This situation can happen as a race condition when updating the cgroup map.
		// In that case, we can try to look for it in the cgroupfs and update the map if found.
		c.cgroupLookupUpdate(cgroupId)
	}
	c.mtx.RLock()
	cgroupInfo := c.cgroups[uint32(cgroupId)]
	c.mtx.RUnlock()
	return cgroupInfo
}

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
