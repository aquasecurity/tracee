package containers

import (
	"bufio"
	"context"
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
	cruntime "github.com/aquasecurity/tracee/pkg/containers/runtime"
)

var cgroupV1HierarchyID int

const cgroupV1Controller = "cpuset"
const cgroupV1FsType = "cgroup"
const cgroupV2FsType = "cgroup2"

// Containers contains information about running containers in the host.
type Containers struct {
	cgroupV1   bool
	cgroupMP   string
	cgroups    map[uint32]CgroupInfo
	deleted    []uint64
	mtx        sync.RWMutex // protecting both cgroups and deleted fields
	enricher   runtimeInfoService
	bpfMapName string
}

// CgroupInfo represents a cgroup dir (might describe a container cgroup dir).
type CgroupInfo struct {
	Path      string
	Container cruntime.ContainerMetadata
	Runtime   cruntime.RuntimeId
	Ctime     time.Time
	expiresAt time.Time
}

// New initializes a Containers object and returns a pointer to it.
// User should further call "Populate" and iterate with Containers data.
func New(sockets cruntime.Sockets, mapName string, debug bool) (*Containers, error) {
	containers := &Containers{
		cgroupV1:   false,
		cgroupMP:   "",
		cgroups:    make(map[uint32]CgroupInfo),
		mtx:        sync.RWMutex{},
		bpfMapName: mapName,
	}

	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); os.IsNotExist(err) {
		if err := containers.initCgroupV1(); err != nil {
			return nil, err
		}
	}

	runtimeService := RuntimeInfoService(sockets)

	//attempt to register for all supported runtimes
	err := runtimeService.Register(cruntime.Containerd, cruntime.ContainerdEnricher)
	if err != nil && debug {
		fmt.Fprintf(os.Stderr, "Enricher: %v\n", err)
	}
	err = runtimeService.Register(cruntime.Crio, cruntime.CrioEnricher)
	if err != nil && debug {
		fmt.Fprintf(os.Stderr, "Enricher: %v\n", err)
	}
	err = runtimeService.Register(cruntime.Docker, cruntime.DockerEnricher)
	if err != nil && debug {
		fmt.Fprintf(os.Stderr, "Enricher: %v\n", err)
	}

	containers.enricher = runtimeService

	return containers, nil
}

// Close executes cleanup logic for Containers object
func (c *Containers) Close() error {
	// if we are on cgroupv1 and previously executed cpuset mounting logic (see function initCgroupV1)
	if c.IsCgroupV1() && strings.HasPrefix(c.cgroupMP, "/tmp") {
		// first unmount the temporary cpuset mount
		err := syscall.Unmount(c.cgroupMP, 0)
		if err != nil {
			return err
		}

		// then remove the dir
		err = os.RemoveAll(c.cgroupMP)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Containers) IsCgroupV1() bool {
	return c.cgroupV1
}

func (c *Containers) GetCgroupV1HID() int {
	return cgroupV1HierarchyID
}

// Populate populates Containers struct by reading mounted proc and cgroups fs.
func (c *Containers) Populate() error {
	if c.cgroupMP == "" {
		err := c.findCgroupMounts()
		if err != nil {
			return err
		}
	}

	return c.populate()
}

// getCgroupV1SSID finds cgroup v1 hierarchy ID.
func (c *Containers) initCgroupV1() error {
	c.cgroupV1 = true
	hierarchyId, err := getCgroupV1HierarchyId()
	if err != nil {
		return err
	}
	cgroupV1HierarchyID = hierarchyId

	inContainer, err := runsOnContainerV1()
	if err != nil {
		fmt.Fprintf(os.Stderr, "containers: failed to detect if running on a cgroupv1 container: %s", err)
		return nil
	}

	if inContainer {
		path, err := os.MkdirTemp("/tmp", "tracee-cpuset")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create cpuset directory %s\n", err)
			return nil
		}

		mountPath, err := filepath.Abs(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get absolute path of cputset mountpoint %s\n", mountPath)
			return nil
		}

		err = mountCpuset(mountPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "containers: failed to mount cgroupv1 controller: %s\n", err)
			return nil
		}

		// now that we know what the mountPath is we can just set it
		c.cgroupMP = mountPath
	}

	return nil
}

// findCgroupMounts finds cgroups v1 and v2 mountpoints.
func (c *Containers) findCgroupMounts() error {
	fsType := cgroupV2FsType
	search := ""
	if c.cgroupV1 {
		fsType = cgroupV1FsType
		search = "cpuset"
	}

	mp, err := searchMountpoint(fsType, search)

	if err != nil {
		return err
	}

	c.cgroupMP = mp
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
	containerId, containerRuntime := getContainerIdFromCgroup(path)
	container := cruntime.ContainerMetadata{
		ContainerId: containerId,
	}

	info := CgroupInfo{
		Path:      path,
		Container: container,
		Runtime:   containerRuntime,
		Ctime:     ctime,
	}

	c.mtx.Lock()
	c.cgroups[uint32(cgroupId)] = info
	c.mtx.Unlock()

	return info, nil
}

// EnrichCgroupInfo checks for a given cgroupId if it is relevant to some running container
// it then calls the runtime info service to gather additional data from the container's runtime
// it returns the retrieved metadata and a relevant error
// this function shouldn't be called twice for the same cgroupId unless attempting a retry
func (c *Containers) EnrichCgroupInfo(cgroupId uint64) (cruntime.ContainerMetadata, error) {
	var metadata cruntime.ContainerMetadata

	c.mtx.RLock()
	info, ok := c.cgroups[uint32(cgroupId)]
	c.mtx.RUnlock()

	//if there is no cgroup anymore for some reason, return early
	if !ok {
		return metadata, fmt.Errorf("no cgroup to enrich")
	}

	containerId := info.Container.ContainerId
	runtime := info.Runtime

	if containerId == "" {
		return metadata, fmt.Errorf("no containerId")
	}

	//There might be a performance overhead with the cancel
	//But, I think it will be negligable since this code path shouldn't be reached too frequently
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	metadata, err := c.enricher.Get(containerId, runtime, ctx)
	defer cancel()
	//if enrichment fails, just return early
	if err != nil {
		return metadata, err
	}

	info.Container = metadata
	c.mtx.Lock()
	//we read the dictionary again to make sure the cgroup still exists
	//otherwise we risk reintroducing it despite not existing
	_, ok = c.cgroups[uint32(cgroupId)]
	if ok {
		c.cgroups[uint32(cgroupId)] = info
	}
	c.mtx.Unlock()

	return metadata, nil
}

var (
	containerIdFromCgroupRegex = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
)

// getContainerIdFromCgroup extracts container id and its runtime from path.
// It returns (containerId, runtime string).
func getContainerIdFromCgroup(cgroupPath string) (string, cruntime.RuntimeId) {
	prevPathComp := ""
	for _, pc := range strings.Split(cgroupPath, "/") {
		if len(pc) < 64 {
			prevPathComp = pc
			continue
		}

		runtime := cruntime.Unknown
		id := strings.TrimSuffix(pc, ".scope")

		switch {
		case strings.HasPrefix(id, "docker-"):
			runtime = cruntime.Docker
			id = strings.TrimPrefix(id, "docker-")
		case strings.HasPrefix(id, "crio-"):
			runtime = cruntime.Crio
			id = strings.TrimPrefix(id, "crio-")
		case strings.HasPrefix(id, "cri-containerd-"):
			runtime = cruntime.Containerd
			id = strings.TrimPrefix(id, "cri-containerd-")
		case strings.Contains(pc, ":cri-containerd:"):
			runtime = cruntime.Containerd
			id = pc[strings.LastIndex(pc, ":cri-containerd:")+len(":cri-containerd:"):]
		case strings.HasPrefix(id, "libpod-"):
			runtime = cruntime.Podman
			id = strings.TrimPrefix(id, "libpod-")
		}

		regex := containerIdFromCgroupRegex
		if matched := regex.MatchString(id); matched {
			if runtime == cruntime.Unknown && prevPathComp == "docker" {
				// non-systemd docker with format: .../docker/01adbf...f26db7f/
				runtime = cruntime.Docker
			}

			// return first match: closest to root dir path component
			// (to have container id of the outer container)
			return id, runtime
		}

		prevPathComp = pc
	}

	// cgroup dirs unrelated to containers provides empty (containerId, runtime)
	return "", cruntime.Unknown
}

// CgroupRemove removes cgroupInfo of deleted cgroup dir from Containers struct.
// NOTE: Expiration logic of 5 seconds to avoid race conditions (if cgroup dir
// event arrives too fast and its cgroupInfo data is still needed).
func (c *Containers) CgroupRemove(cgroupId uint64, hierarchyID uint32) {
	if c.cgroupV1 && int(hierarchyID) != cgroupV1HierarchyID {
		// For cgroup v1, we only need to look at one controller
		return
	}

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

	if info, ok := c.cgroups[uint32(cgroupId)]; ok {
		info.expiresAt = now.Add(5 * time.Second)
		c.cgroups[uint32(cgroupId)] = info
		c.deleted = append(c.deleted, cgroupId)
	}
}

// CgroupMkdir adds cgroupInfo of a created cgroup dir to Containers struct.
func (c *Containers) CgroupMkdir(cgroupId uint64, subPath string, hierarchyID uint32) (CgroupInfo, error) {
	if c.cgroupV1 && int(hierarchyID) != cgroupV1HierarchyID {
		// For cgroup v1, we only need to look at one controller
		return CgroupInfo{}, nil
	}
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
		if strings.HasPrefix(v.Container.ContainerId, containerID) {
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

// GetContainers provides a list of all existing containers.
func (c *Containers) GetContainers() map[uint32]CgroupInfo {
	conts := map[uint32]CgroupInfo{}
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	for id, v := range c.cgroups {
		if v.Container.ContainerId != "" && v.expiresAt.IsZero() {
			conts[id] = v
		}
	}
	return conts
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

func (c *Containers) PopulateBpfMap(bpfModule *libbpfgo.Module) error {
	containersMap, err := bpfModule.GetMap(c.bpfMapName)
	if err != nil {
		return err
	}

	c.mtx.RLock()
	for cgroupIdLsb, info := range c.cgroups {
		if info.Container.ContainerId != "" {
			state := containerExisted
			err = containersMap.Update(unsafe.Pointer(&cgroupIdLsb), unsafe.Pointer(&state))
		}
	}
	c.mtx.RUnlock()

	return err
}

func (c *Containers) RemoveFromBpfMap(bpfModule *libbpfgo.Module, cgroupId uint64, hierarchyID uint32) error {
	if c.cgroupV1 && int(hierarchyID) != cgroupV1HierarchyID {
		// For cgroup v1, we only need to look at one controller
		return nil
	}

	containersMap, err := bpfModule.GetMap(c.bpfMapName)
	if err != nil {
		return err
	}

	cgroupIdLsb := uint32(cgroupId)
	return containersMap.DeleteKey(unsafe.Pointer(&cgroupIdLsb))
}
