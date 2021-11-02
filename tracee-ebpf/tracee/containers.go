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
	cgroupv1     bool
	cgroupv1mp   string
	cgroupv2     bool
	cgroupv2mp   string
	cgroupContId map[uint32]string
}

// InitContainers initializes a Containers object and returns a pointer to it.
// User should further call "Populate" and iterate with Containers data.
func InitContainers() *Containers {
	return &Containers{
		cgroupContId: make(map[uint32]string),
		cgroupv1:     false,
		cgroupv2:     false,
		cgroupv1mp:   "",
		cgroupv2mp:   "",
	}
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
	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Split(scanner.Text(), " ")
		mountpoint := sline[1]
		fstype := sline[2]
		if fstype == "cgroup" {
			if strings.Contains(mountpoint, "cgroup/pids") {
				c.cgroupv1 = true
				c.cgroupv1mp = mountpoint
			}
		} else if fstype == "cgroup2" {
			c.cgroupv2 = true
			c.cgroupv2mp = mountpoint
		}
	}
	_ = file.Close()

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

	if c.cgroupv1 {
		err := filepath.WalkDir(c.cgroupv1mp, fn)
		if err != nil {
			return err
		}
	}
	if c.cgroupv2 {
		err := filepath.WalkDir(c.cgroupv2mp, fn)
		if err != nil {
			return err
		}
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
