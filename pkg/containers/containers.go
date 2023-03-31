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

	"github.com/aquasecurity/tracee/pkg/cgroup"
	cruntime "github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// Containers contains information about running containers in the host.
type Containers struct {
	cgroups    *cgroup.Cgroups
	cgroupsMap map[uint32]CgroupInfo
	deleted    []uint64
	mtx        sync.RWMutex // protecting both cgroups and deleted fields
	enricher   runtimeInfoService
	bpfMapName string
}

// CgroupInfo represents a cgroup dir (might describe a container cgroup dir).
type CgroupInfo struct {
	Path          string
	Container     cruntime.ContainerMetadata
	Runtime       cruntime.RuntimeId
	ContainerRoot bool // is the cgroup directory the root of its container
	Ctime         time.Time
	expiresAt     time.Time
}

// New initializes a Containers object and returns a pointer to it.
// User should further call "Populate" and iterate with Containers data.
func New(
	cgroups *cgroup.Cgroups,
	sockets cruntime.Sockets,
	mapName string,
) (
	*Containers,
	error,
) {
	containers := &Containers{
		cgroups:    cgroups,
		cgroupsMap: make(map[uint32]CgroupInfo),
		mtx:        sync.RWMutex{},
		bpfMapName: mapName,
	}

	runtimeService := RuntimeInfoService(sockets)

	//attempt to register for all supported runtimes
	err := runtimeService.Register(cruntime.Containerd, cruntime.ContainerdEnricher)
	if err != nil {
		logger.Debugw("Enricher", "error", err)
	}
	err = runtimeService.Register(cruntime.Crio, cruntime.CrioEnricher)
	if err != nil {
		logger.Debugw("Enricher", "error", err)
	}
	err = runtimeService.Register(cruntime.Docker, cruntime.DockerEnricher)
	if err != nil {
		logger.Debugw("Enricher", "error", err)
	}
	// podman and docker use compatible http apis, therefore the docker enricher
	// works for podman.
	err = runtimeService.Register(cruntime.Podman, cruntime.DockerEnricher)
	if err != nil {
		logger.Debugw("Enricher", "error", err)
	}

	containers.enricher = runtimeService

	return containers, nil
}

// Close executes cleanup logic for Containers object
func (c *Containers) Close() error {
	return nil
}

func (c *Containers) GetDefaultCgroupHierarchyID() int {
	return c.cgroups.GetDefaultCgroupHierarchyID()
}

func (c *Containers) GetCgroupVersion() cgroup.CgroupVersion {
	return c.cgroups.GetDefaultCgroup().GetVersion()
}

// Populate populates Containers struct by reading mounted proc and cgroups fs.
func (c *Containers) Populate() error {
	return c.populate()
}

// GetContainerIdFromTaskDir gets a containerID from a given task or process
// directory path
func GetContainerIdFromTaskDir(taskPath string) (string, error) {
	containerId := ""
	taskPath = fmt.Sprintf("%s/cgroup", taskPath)
	cgroupFile, err := os.Open(taskPath)
	if err != nil {
		return containerId, errfmt.WrapError(err)
	}
	defer func() {
		if err := cgroupFile.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	scanner := bufio.NewScanner(cgroupFile)
	for scanner.Scan() {
		containerId, _, _ := getContainerIdFromCgroup(scanner.Text())
		if containerId != "" {
			break
		}
	}
	return containerId, nil
}

// populate walks the cgroup fs informing CgroupUpdate() about existing dirs.
func (c *Containers) populate() error {
	fn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Errorw("WalkDir func", "error", err)
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

		return errfmt.WrapError(err)
	}

	return filepath.WalkDir(c.cgroups.GetDefaultCgroup().GetMountPoint(), fn)
}

// CgroupUpdate checks if given path belongs to a known container runtime,
// saving container information in Containers CgroupInfo map.
// NOTE: ALL given cgroup dir paths are stored in CgroupInfo map.
func (c *Containers) CgroupUpdate(cgroupId uint64, path string, ctime time.Time) (CgroupInfo, error) {
	containerId, containerRuntime, isRoot := getContainerIdFromCgroup(path)
	container := cruntime.ContainerMetadata{
		ContainerId: containerId,
	}

	info := CgroupInfo{
		Path:          path,
		Container:     container,
		Runtime:       containerRuntime,
		ContainerRoot: isRoot,
		Ctime:         ctime,
	}

	c.mtx.Lock()
	c.cgroupsMap[uint32(cgroupId)] = info
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
	info, ok := c.cgroupsMap[uint32(cgroupId)]
	c.mtx.RUnlock()

	//if there is no cgroup anymore for some reason, return early
	if !ok {
		return metadata, errfmt.Errorf("no cgroup to enrich")
	}

	containerId := info.Container.ContainerId
	runtime := info.Runtime

	if containerId == "" {
		return metadata, errfmt.Errorf("no containerId")
	}

	//There might be a performance overhead with the cancel
	//But, I think it will be negligible since this code path shouldn't be reached too frequently
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	metadata, err := c.enricher.Get(containerId, runtime, ctx)
	defer cancel()
	//if enrichment fails, just return early
	if err != nil {
		return metadata, errfmt.WrapError(err)
	}

	info.Container = metadata
	c.mtx.Lock()
	//we read the dictionary again to make sure the cgroup still exists
	//otherwise we risk reintroducing it despite not existing
	_, ok = c.cgroupsMap[uint32(cgroupId)]
	if ok {
		c.cgroupsMap[uint32(cgroupId)] = info
	}
	c.mtx.Unlock()

	return metadata, nil
}

var (
	containerIdFromCgroupRegex = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
)

// getContainerIdFromCgroup extracts container id and its runtime from path.
// It returns (containerId, runtime string).
func getContainerIdFromCgroup(cgroupPath string) (string, cruntime.RuntimeId, bool) {
	cgroupParts := strings.Split(cgroupPath, "/")

	// search from the end to get the most inner container id
	for i := len(cgroupParts) - 1; i >= 0; i = i - 1 {
		pc := cgroupParts[i]
		// container id is at least 64 characters long
		if len(pc) < 64 {
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

		if matched := containerIdFromCgroupRegex.MatchString(id); matched {
			if runtime == cruntime.Unknown && i > 0 && cgroupParts[i-1] == "docker" {
				// non-systemd docker with format: .../docker/01adbf...f26db7f/
				runtime = cruntime.Docker
			}

			// return first match: closest to root dir path component
			// (to have container id of the outer container)
			// container root determined by being matched on the last path part
			return id, runtime, i == len(cgroupParts)-1
		}
	}
	// cgroup dirs unrelated to containers provides empty (containerId, runtime)
	return "", cruntime.Unknown, false
}

// CgroupRemove removes cgroupInfo of deleted cgroup dir from Containers struct.
// NOTE: Expiration logic of 5 seconds to avoid race conditions (if cgroup dir
// event arrives too fast and its cgroupInfo data is still needed).
func (c *Containers) CgroupRemove(cgroupId uint64, hierarchyID uint32) {
	// cgroupv1: no need to check other controllers than the default
	switch c.cgroups.GetDefaultCgroup().(type) {
	case *cgroup.CgroupV1:
		if c.cgroups.GetDefaultCgroupHierarchyID() != int(hierarchyID) {
			return
		}
	}

	now := time.Now()
	var deleted []uint64
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// process previously deleted cgroupInfo data (deleted cgroup dirs)
	for _, id := range c.deleted {
		info := c.cgroupsMap[uint32(id)]
		if now.After(info.expiresAt) {
			delete(c.cgroupsMap, uint32(id))
		} else {
			deleted = append(deleted, id)
		}
	}
	c.deleted = deleted

	if info, ok := c.cgroupsMap[uint32(cgroupId)]; ok {
		info.expiresAt = now.Add(5 * time.Second)
		c.cgroupsMap[uint32(cgroupId)] = info
		c.deleted = append(c.deleted, cgroupId)
	}
}

// CgroupMkdir adds cgroupInfo of a created cgroup dir to Containers struct.
func (c *Containers) CgroupMkdir(cgroupId uint64, subPath string, hierarchyID uint32) (CgroupInfo, error) {
	// cgroupv1: no need to check other controllers than the default
	switch c.cgroups.GetDefaultCgroup().(type) {
	case *cgroup.CgroupV1:
		if c.cgroups.GetDefaultCgroupHierarchyID() != int(hierarchyID) {
			return CgroupInfo{}, nil
		}
	}

	// Find container cgroup dir path to get directory stats
	curTime := time.Now()
	path, err := cgroup.GetCgroupPath(c.cgroups.GetDefaultCgroup().GetMountPoint(), cgroupId, subPath)
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

// FindContainerCgroupID32LSB returns the 32 LSB of the Cgroup ID for a given container ID
func (c *Containers) FindContainerCgroupID32LSB(containerID string) []uint32 {
	var cgroupIDs []uint32
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	for k, v := range c.cgroupsMap {
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
		path, err := cgroup.GetCgroupPath(c.cgroups.GetDefaultCgroup().GetMountPoint(), cgroupId, "")
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
	cgroupInfo := c.cgroupsMap[uint32(cgroupId)]
	c.mtx.RUnlock()

	return cgroupInfo
}

// GetContainers provides a list of all existing containers.
func (c *Containers) GetContainers() map[uint32]CgroupInfo {
	conts := map[uint32]CgroupInfo{}
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	for id, v := range c.cgroupsMap {
		if v.ContainerRoot && v.expiresAt.IsZero() {
			conts[id] = v
		}
	}
	return conts
}

// CgroupExists checks if there is a cgroupInfo data of a given cgroupId.
func (c *Containers) CgroupExists(cgroupId uint64) bool {
	c.mtx.RLock()
	_, ok := c.cgroupsMap[uint32(cgroupId)]
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
		return errfmt.WrapError(err)
	}

	c.mtx.RLock()
	for cgroupIdLsb, info := range c.cgroupsMap {
		if info.ContainerRoot {
			state := containerExisted
			err = containersMap.Update(unsafe.Pointer(&cgroupIdLsb), unsafe.Pointer(&state))
		}
	}
	c.mtx.RUnlock()

	return errfmt.WrapError(err)
}

func (c *Containers) RemoveFromBpfMap(bpfModule *libbpfgo.Module, cgroupId uint64, hierarchyID uint32) error {
	// cgroupv1: no need to check other controllers than the default
	switch c.cgroups.GetDefaultCgroup().(type) {
	case *cgroup.CgroupV1:
		if c.cgroups.GetDefaultCgroupHierarchyID() != int(hierarchyID) {
			return nil
		}
	}

	containersMap, err := bpfModule.GetMap(c.bpfMapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	cgroupIdLsb := uint32(cgroupId)
	return containersMap.DeleteKey(unsafe.Pointer(&cgroupIdLsb))
}
