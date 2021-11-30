package tracee

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// Containers contain information about host running containers in the host.
type Containers struct {
	cgroupV1 bool
	cgroupMP string
	cgroups  map[uint32]CgroupInfo
	deleted  []uint64
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

func (c *Containers) CgroupLookupUpdate(cgroupId uint64) error {
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
		c.cgroups[uint32(cgroupId)] = CgroupInfo{}
	}

	return err
}

// check if path belongs to a known container runtime and
// add cgroupId with a matching container id, extracted from path
func (c *Containers) CgroupUpdate(cgroupId uint64, path string) (CgroupInfo, error) {
	info := CgroupInfo{Path: path}

	for _, pc := range strings.Split(path, "/") {
		if len(pc) < 64 {
			continue
		}
		containerId, runtime := c.getContainerIdFromCgroup(pc)
		if containerId == "" {
			continue
		}
		info.ContainerId = containerId
		info.Runtime = runtime
	}

	c.cgroups[uint32(cgroupId)] = info
	return info, nil
}

// extract container id and container runtime from path
func (c *Containers) getContainerIdFromCgroup(pathComponent string) (string, string) {
	runtime := "unknown"
	path := strings.TrimSuffix(pathComponent, ".scope")

	if strings.HasPrefix(path, "docker-") {
		runtime = "docker"
		path = strings.TrimPrefix(path, "docker-")
		goto check
	}
	if strings.HasPrefix(path, "crio-") {
		runtime = "crio"
		path = strings.TrimPrefix(path, "crio-")
		goto check
	}
	if strings.HasPrefix(path, "cri-containerd-") {
		runtime = "containerd"
		path = strings.TrimPrefix(path, "cri-containerd-")
		goto check
	}
	if strings.HasPrefix(path, "libpod-") {
		runtime = "podman"
		path = strings.TrimPrefix(path, "libpod-")
		goto check
	}

check:
	if matched, _ := regexp.MatchString(`^[A-Fa-f0-9]{64}$`, path); !matched {
		return "", ""
	}

	return path, runtime
}

func (c *Containers) CgroupRemove(cgroupId uint64) {
	now := time.Now()
	// prune containers that have been removed more than 5 seconds ago
	var deleted []uint64
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
	for _, v := range c.cgroups {
		if v.ContainerId != "" && v.expiresAt.IsZero() {
			conts = append(conts, v.ContainerId)
		}
	}
	return conts
}

func (c *Containers) GetCgroupInfo(cgroupId uint64) CgroupInfo {
	return c.cgroups[uint32(cgroupId)]
}

func (c *Containers) CgroupExists(cgroupId uint64) bool {
	if _, ok := c.cgroups[uint32(cgroupId)]; ok {
		return true
	}
	return false
}

const (
	containerExisted uint8 = iota + 1
	containerCreated
	containerStarted
)

func (c *Containers) PopulateBpfMap(bpfModule *bpf.Module) error {
	containersMap, err := bpfModule.GetMap("containers_map")
	if err != nil {
		return err
	}

	for cgroupIdLsb, info := range c.cgroups {
		if info.ContainerId != "" {
			state := containerExisted
			err = containersMap.Update(unsafe.Pointer(&cgroupIdLsb), unsafe.Pointer(&state))
		}
	}

	return err
}

func (c *Containers) RemoveFromBpfMap(bpfModule *bpf.Module, cgroupId uint64) error {
	containersMap, err := bpfModule.GetMap("containers_map")
	if err != nil {
		return err
	}

	cgroupIdLsb := uint32(cgroupId)
	return containersMap.DeleteKey(unsafe.Pointer(&cgroupIdLsb))
}
