package tracee

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Containers contain information about host running containers in the host.
type Containers struct {
	cgroupV1     bool
	cgroupMP     string
	cgroupContId map[uint32]string
}

// InitContainers initializes a Containers object and returns a pointer to it.
// User should further call "Populate" and iterate with Containers data.
func InitContainers() *Containers {
	cgroupV1 := false
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); os.IsNotExist(err) {
		cgroupV1 = true
	}

	return &Containers{
		cgroupV1:     cgroupV1,
		cgroupMP:     "",
		cgroupContId: make(map[uint32]string),
	}
}

func (c *Containers) IsCgroupV1() bool {
	return c.cgroupV1
}

// GetContainers provides a list of all added containers by their uuid.
func (c *Containers) GetContainers() []string {
	var conts []string
	for _, v := range c.cgroupContId {
		conts = append(conts, v)
	}
	return conts
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

		return c.CgroupUpdate(stat.Ino, path)
	}

	if c.cgroupMP == "" {
		return fmt.Errorf("could not determine cgroup mount point")
	}

	err := filepath.WalkDir(c.cgroupMP, fn)
	if err != nil {
		return err
	}

	return nil
}

// check if path belongs to a known container runtime and
// add cgroupId with a matching container id, extracted from path
func (c *Containers) CgroupUpdate(cgroupId uint64, path string) error {
	pathComponents := strings.Split(path, "/")

	for _, pc := range pathComponents {
		if len(pc) < 64 {
			continue
		}
		containerId, _ := c.getContainerIdFromCgroup(pc)
		if containerId == "" {
			continue
		}
		c.cgroupContId[uint32(cgroupId)] = containerId

		return nil
	}

	return nil
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
	delete(c.cgroupContId, uint32(cgroupId))
}

func (c *Containers) GetContainerId(cgroupId uint64) string {
	return c.cgroupContId[uint32(cgroupId)]
}
