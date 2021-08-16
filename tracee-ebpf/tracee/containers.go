package tracee

import (
	"bufio"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Containers contain information about host running containers in the host.
type Containers struct {
	cgroupv1   bool
	cgroupv1mp string
	cgroupv2   bool
	cgroupv2mp string
	mapContIds map[string][]int32
}

// InitContainers initializes a Containers object and returns a pointer to it.
// User should further call "Populate" and iterate with Containers data.
func InitContainers() *Containers {
	return &Containers{
		mapContIds: make(map[string][]int32, 0),
		cgroupv1:   false,
		cgroupv2:   false,
		cgroupv1mp: "",
		cgroupv2mp: "",
	}
}

// addContainer adds a container given its uuid.
func (c *Containers) addContainer(contId string) {
	_, ok := c.mapContIds[contId]
	if !ok {
		c.mapContIds[contId] = make([]int32, 0)
	}
}

// GetContainers provides a list of all added containers by their uuid.
func (c *Containers) GetContainers() []string {
	var conts []string
	for k := range c.mapContIds {
		conts = append(conts, k)
	}
	return conts
}

// addPid will add a given pid string to an existing container by given uuid.
// It will also create the container if given container uuid does not exist.
func (c *Containers) addPid(contId string, pid int32) {
	c.addContainer(contId)
	c.mapContIds[contId] = append(c.mapContIds[contId], pid)
}

func (c *Containers) GetPids(contId string) []int32 {
	return c.mapContIds[contId]
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

// populate prepares the regex(es) to be used for the population to be done in
// proc walk.
func (c *Containers) populate() error {

	if c.cgroupv1 {
		var r []string
		// docker:  <cgroupv1mp>/<random>/docker/<id>/tasks
		r = append(r, ".*docker.*(.{64})/tasks$")
		// podman:  <cgroupv1mp>/<random>/libpod-<id>.scope/tasks
		r = append(r, ".*libpod.*(.{64})\\.scope/tasks$")
		// generic: <cgroupv1mp>/<random>/<id>.scope/tasks
		r = append(r, ".*(.{64})\\.scope/tasks$")

		err := c.populateProcWalk(c.cgroupv1mp, r)
		if err != nil {
			return err
		}
	}
	if c.cgroupv2 {
		var r []string
		// docker:  <cgroupv2mp>/<random>/docker-<id>.scope/cgroup.procs
		r = append(r, ".*docker.*(.{64})\\.scope/cgroup.procs$")
		// podman:  <cgroupv2mp>/<random>/libpod-<id>.scope/cgroup.procs
		r = append(r, ".*libpod.*(.{64})\\.scope/cgroup.procs$")
		// generic: <cgroupv2mp>/<random>/<id>.scope/cgroup.procs
		r = append(r, ".*(.{64})\\.scope/cgroup.procs$")

		err := c.populateProcWalk(c.cgroupv2mp, r)
		if err != nil {
			return err
		}
	}

	return nil
}

// populateProcWalk walks through procfs for cgroups (v1 & v2) filesystems and
// find files based on given regex(es). It also extracts containers
// information from found files and creates containers by their uuid AND adds
// running pids to those containers.
func (c *Containers) populateProcWalk(basedir string, allstr []string) error {

	var allres []*regexp.Regexp
	allres = make([]*regexp.Regexp, len(allstr))
	for j := 0; j < len(allstr); j++ {
		allres[j] = regexp.MustCompile(basedir + allstr[j])
	}
	err := filepath.WalkDir(basedir,
		func(fn string, fi fs.DirEntry, err error) error {
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				return nil
			}
			for l := 0; l < len(allres); l++ {
				res := allres[l].FindStringSubmatch(fn)
				if len(res) == 0 {
					continue
				}
				contId := res[1] // 1st regexp match (Id)
				c.addContainer(contId)
				buf, e := ioutil.ReadFile(fn) // res[0] or fn == .tasks or .procs file
				if e != nil {
					return e // error if can't read pids file
				}
				for _, pid := range strings.Split(string(buf), "\n") {
					if len(pid) > 0 {
						var pidInt int32
						_, err = fmt.Sscanf(pid, "%d", &pidInt)
						if err != nil {
							continue // ignore sscanf errors
						}
						c.addPid(contId, pidInt)
					}
				}
				break // a single match is enough
			}
			return nil
		})

	return err
}
