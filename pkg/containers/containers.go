package containers

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/k8s"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type Container struct {
	ContainerId string
	CreatedAt   time.Time
	Runtime     runtime.RuntimeId
	Name        string
	Image       string
	ImageDigest string
	Pod         Pod
}

type Pod struct {
	Name      string
	Namespace string
	UID       string
	Sandbox   bool
}

// Manager contains information about running containers in the host.
type Manager struct {
	cgroups      *cgroup.Cgroups
	cgroupsMap   map[uint32]CgroupDir
	containerMap map[string]Container
	deleted      []uint64
	lock         sync.RWMutex // protecting both cgroups and deleted fields
	enricher     runtime.Service
	bpfMapName   string
}

// CgroupDir represents a cgroup dir (which may be a container cgroup dir).
type CgroupDir struct {
	Path          string
	ContainerId   string
	ContainerRoot bool // is the cgroup directory the root of its container
	Ctime         time.Time
	Dead          bool // is the cgroup deleted
	expiresAt     time.Time
}

// New initializes a Containers object and returns a pointer to it. User should further
// call "Populate" and iterate with Containers data.
func New(
	noContainersEnrich bool,
	cgroups *cgroup.Cgroups,
	sockets runtime.Sockets,
	mapName string,
) (
	*Manager,
	error,
) {
	containers := &Manager{
		cgroups:      cgroups,
		cgroupsMap:   make(map[uint32]CgroupDir),
		containerMap: make(map[string]Container),
		lock:         sync.RWMutex{},
		bpfMapName:   mapName,
	}

	// Attempt to register enrichers for all supported runtimes.

	if !noContainersEnrich {
		runtimeService := runtime.NewService(sockets)

		err := runtimeService.Register(runtime.Containerd, runtime.ContainerdEnricher)
		if err != nil {
			logger.Debugw("Enricher", "error", err)
		}
		err = runtimeService.Register(runtime.Crio, runtime.CrioEnricher)
		if err != nil {
			logger.Debugw("Enricher", "error", err)
		}
		err = runtimeService.Register(runtime.Docker, runtime.DockerEnricher)
		if err != nil {
			logger.Debugw("Enricher", "error", err)
		}
		// Docker enricher also works for podman (compatible HTTP apis)
		err = runtimeService.Register(runtime.Podman, runtime.DockerEnricher)
		if err != nil {
			logger.Debugw("Enricher", "error", err)
		}

		containers.enricher = runtimeService
	}

	return containers, nil
}

// Close executes cleanup logic for Containers object.
func (c *Manager) Close() error {
	return nil
}

func (c *Manager) GetDefaultCgroupHierarchyID() int {
	return c.cgroups.GetDefaultCgroupHierarchyID()
}

func (c *Manager) GetCgroupVersion() cgroup.CgroupVersion {
	return c.cgroups.GetDefaultCgroup().GetVersion()
}

// Populate populates Containers struct by reading mounted proc and cgroups fs.
func (c *Manager) Populate() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.populate()
}

// populate walks the cgroup fs informing CgroupUpdate() about existing dirs.
func (c *Manager) populate() error {
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
		_, _, err = c.cgroupUpdate(inodeNumber, path, statusChange, false)

		return errfmt.WrapError(err)
	}

	return filepath.WalkDir(c.cgroups.GetDefaultCgroup().GetMountPoint(), fn)
}

// cgroupUpdate checks if given path belongs to a known container runtime, saving
// container information in Containers CgroupInfo map.
func (c *Manager) cgroupUpdate(
	cgroupId uint64, path string, ctime time.Time, dead bool,
) (CgroupDir, Container, error) {
	// NOTE: ALL given cgroup dir paths are stored in CgroupInfo map.
	// NOTE: not thread-safe, lock handled by external calling function

	// Cgroup paths should be stored and evaluated relative to the mountpoint.
	path = strings.TrimPrefix(path, c.cgroups.GetDefaultCgroup().GetMountPoint())
	containerId, containerRuntime, isRoot := parseContainerIdFromCgroupPath(path)

	info := CgroupDir{
		Path:          path,
		ContainerId:   containerId,
		ContainerRoot: isRoot,
		Ctime:         ctime,
		Dead:          dead,
	}

	container := Container{
		ContainerId: containerId,
		Runtime:     containerRuntime,
		CreatedAt:   ctime,
	}

	c.cgroupsMap[uint32(cgroupId)] = info
	c.containerMap[containerId] = container

	return info, container, nil
}

// EnrichCgroupInfo checks for a given cgroupId if it is relevant to some running
// container. It then calls the runtime info service to gather additional data from the
// container's runtime. Should not be called twice for the same cgroupId unless attempting a retry.
//
// Returns the retrieved metadata and a relevant error.
// If the given cgroup does not belong to a container, no error will be returned, but the
// returned metadata's containerId will be empty. This should be checked separately.
func (c *Manager) EnrichCgroupInfo(cgroupId uint64) (Container, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var cont Container
	info, ok := c.cgroupsMap[uint32(cgroupId)]

	// if there is no cgroup anymore for some reason, return early
	if !ok {
		return cont, errfmt.Errorf("cgroup %d not found, won't enrich", cgroupId)
	}

	containerId := info.ContainerId

	if containerId == "" {
		// not a container, nothing to do
		cont.ContainerId = ""
		return cont, nil
	}

	container := c.containerMap[containerId]

	isMikubeOrKind := k8s.IsMinkube() || k8s.IsKind()
	if info.Dead && !isMikubeOrKind {
		return cont, errfmt.Errorf("container %s already deleted in path %s", containerId, info.Path)
	}

	if container.Image != "" {
		// If already enriched (from control plane) - short circuit and return
		return container, nil
	}

	// There might be a performance overhead with the cancel
	// But, I think it will be negligible since this code path shouldn't be reached too frequently
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	enrichRes, err := c.enricher.Get(ctx, containerId, container.Runtime)
	defer cancel()
	// if enrichment fails, just return early
	if err != nil {
		return cont, errfmt.WrapError(err)
	}

	// we read the dictionary again to make sure the cgroup still exists
	// otherwise we risk reintroducing it despite not existing
	_, ok = c.cgroupsMap[uint32(cgroupId)]
	if ok {
		container = Container{
			ContainerId: containerId,
			Name:        enrichRes.ContName,
			Image:       enrichRes.Image,
			ImageDigest: enrichRes.ImageDigest,
			Pod: Pod{
				Name:      enrichRes.PodName,
				Namespace: enrichRes.Namespace,
				UID:       enrichRes.UID,
				Sandbox:   enrichRes.Sandbox,
			},
		}
		c.cgroupsMap[uint32(cgroupId)] = info
		c.containerMap[containerId] = container
	}

	return cont, nil
}

var (
	containerIdFromCgroupRegex       = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	gardenContainerIdFromCgroupRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){4}$`)
)

// parseContainerIdFromCgroupPath extracts container id and its runtime from path. It returns
// the container id, the runtime string and a bool telling if the container is the root of
// its cgroupfs hierarchy.
func parseContainerIdFromCgroupPath(cgroupPath string) (string, runtime.RuntimeId, bool) {
	cgroupParts := strings.Split(cgroupPath, "/")

	// search from the end to get the most inner container id
	for i := len(cgroupParts) - 1; i >= 0; i = i - 1 {
		pc := cgroupParts[i]
		if len(pc) < 28 {
			continue // container id is at least 28 characters long
		}

		contRuntime := runtime.Unknown
		id := strings.TrimSuffix(pc, ".scope")

		switch {
		case strings.HasPrefix(id, "docker-"):
			contRuntime = runtime.Docker
			id = strings.TrimPrefix(id, "docker-")
		case strings.HasPrefix(id, "crio-"):
			contRuntime = runtime.Crio
			id = strings.TrimPrefix(id, "crio-")
		case strings.HasPrefix(id, "cri-containerd-"):
			contRuntime = runtime.Containerd
			id = strings.TrimPrefix(id, "cri-containerd-")
		case strings.Contains(pc, ":cri-containerd:"):
			contRuntime = runtime.Containerd
			id = pc[strings.LastIndex(pc, ":cri-containerd:")+len(":cri-containerd:"):]
		case strings.HasPrefix(id, "libpod-"):
			contRuntime = runtime.Podman
			id = strings.TrimPrefix(id, "libpod-")
		}

		if contRuntime != runtime.Unknown {
			// Return the first match, closest to the root dir path component, so that the
			// container id of the outer container is returned. The container root is
			// determined by being matched on the last path part.
			return id, contRuntime, i == len(cgroupParts)-1
		}

		if matched := containerIdFromCgroupRegex.MatchString(id); matched && i > 0 {
			prevPart := cgroupParts[i-1]
			if prevPart == "docker" {
				// non-systemd docker with format: .../docker/01adbf...f26db7f/
				contRuntime = runtime.Docker
			}
			if prevPart == "actions_job" {
				// non-systemd docker with format in GitHub Actions: .../actions_job/01adbf...f26db7f/
				contRuntime = runtime.Docker
			}
			if strings.HasPrefix(prevPart, "pod") {
				// generic containerd path with format: ...kubepods/<besteffort|burstable>/podXXX/01adbf...f26db7f/
				// NOTE: this workaround may turn out to be wrong, and other runtime distributions may use the same path pattern.
				// The fix relies on us finding this kind of pattern only in containerd envs and being explicitly mentioned in their source code.
				// If this ever doesn't work out, we will need to match the runtime based on the running kubelet daemon.
				contRuntime = runtime.Containerd
			}

			// Return the first match, closest to the root dir path component, so that the
			// container id of the outer container is returned. The container root is
			// determined by being matched on the last path part.
			return id, contRuntime, i == len(cgroupParts)-1
		}

		// Special case: Garden. Garden doesn't have a container enricher implemented,
		// but, still, tracee needs to identify garden containers ids in the events.
		if matched := gardenContainerIdFromCgroupRegex.MatchString(id); matched {
			contRuntime = runtime.Garden
			return id, contRuntime, i == len(cgroupParts)-1
		}
	}

	// cgroup dirs unrelated to containers provides empty (containerId, runtime)
	return "", runtime.Unknown, false
}

// CgroupRemove removes cgroupInfo of deleted cgroup dir from Containers struct. There is
// an expiration logic of 30 seconds to avoid race conditions (if cgroup dir event arrives
// too fast and its cgroupInfo data is still needed).
func (c *Manager) CgroupRemove(cgroupId uint64, hierarchyID uint32) {
	const expiryTime = 30 * time.Second
	// cgroupv1: no need to check other controllers than the default
	switch c.cgroups.GetDefaultCgroup().(type) {
	case *cgroup.CgroupV1:
		if c.cgroups.GetDefaultCgroupHierarchyID() != int(hierarchyID) {
			return
		}
	}

	now := time.Now()
	var deleted []uint64
	c.lock.Lock()
	defer c.lock.Unlock()

	// process previously deleted cgroupInfo data (deleted cgroup dirs)
	for _, id := range c.deleted {
		info := c.cgroupsMap[uint32(id)]
		if now.After(info.expiresAt) {
			contId := c.cgroupsMap[uint32(id)].ContainerId
			delete(c.cgroupsMap, uint32(id))
			delete(c.containerMap, contId)
		} else {
			deleted = append(deleted, id)
		}
	}
	c.deleted = deleted

	if info, ok := c.cgroupsMap[uint32(cgroupId)]; ok {
		info.expiresAt = now.Add(expiryTime)
		info.Dead = true
		c.cgroupsMap[uint32(cgroupId)] = info
		c.deleted = append(c.deleted, cgroupId)
	}
}

// CgroupMkdir adds cgroupInfo of a created cgroup dir to Containers struct.
func (c *Manager) CgroupMkdir(cgroupId uint64, subPath string, hierarchyID uint32) (CgroupDir, Container, error) {
	// cgroupv1: no need to check other controllers than the default
	switch c.cgroups.GetDefaultCgroup().(type) {
	case *cgroup.CgroupV1:
		if c.cgroups.GetDefaultCgroupHierarchyID() != int(hierarchyID) {
			return CgroupDir{}, Container{}, nil
		}
	}

	// Find container cgroup dir path to get directory stats
	c.lock.Lock()
	defer c.lock.Unlock()
	curTime := time.Now()
	path, ctime, err := cgroup.GetCgroupPath(c.cgroups.GetDefaultCgroup().GetMountPoint(), cgroupId, subPath)
	if err == nil {
		// Add cgroupInfo to Containers struct w/ found path (and its last modification time)
		return c.cgroupUpdate(cgroupId, path, ctime, false)
	}

	// No entry found: container may have already exited.
	// Add cgroupInfo to Containers struct with existing data.
	// In this case, ctime is just an estimation (current time).
	return c.cgroupUpdate(cgroupId, subPath, curTime, true)
}

// FindContainerCgroupID32LSB returns the 32 LSB of the Cgroup ID for a given container ID.
func (c *Manager) FindContainerCgroupID32LSB(containerID string) ([]uint32, error) {
	var cgroupIDs []uint32
	c.lock.RLock()
	defer c.lock.RUnlock()
	for k, v := range c.cgroupsMap {
		if strings.HasPrefix(v.ContainerId, containerID) {
			cgroupIDs = append(cgroupIDs, k)
		}
	}

	if cgroupIDs == nil {
		return nil, errfmt.Errorf("container id not found: %s", containerID)
	}
	if len(cgroupIDs) > 1 {
		return cgroupIDs, errfmt.Errorf("container id is ambiguous: %s", containerID)
	}

	return cgroupIDs, nil
}

// GetCgroupInfo returns the contents of the Containers struct cgroupInfo data of a given cgroupId.
func (c *Manager) GetCgroupInfo(cgroupId uint64) (CgroupDir, Container) {
	if !c.CgroupExists(cgroupId) {
		// There should be a cgroupInfo for the given cgroupId but there isn't. Tracee
		// might be processing an event for an already created container before the
		// CgroupMkdirEventID logic was executed, for example.

		// Get the path for given cgroupId from cgroupfs and update its cgroupInfo in the
		// Containers struct. An empty subPath will make GetCgroupPath() to WALK ALL THE
		// cgroupfs directories, until it finds the directory of given cgroupId.
		var cgroupInfo CgroupDir
		var container Container

		c.lock.Lock()
		defer c.lock.Unlock()

		path, ctime, err := cgroup.GetCgroupPath(c.cgroups.GetDefaultCgroup().GetMountPoint(), cgroupId, "")
		if err == nil {
			cgroupInfo, container, err = c.cgroupUpdate(cgroupId, path, ctime, false)
			if err != nil {
				logger.Errorw("cgroupUpdate", "error", err)
			}
		}

		// No entry found: cgroup may have already been deleted.
		// Add cgroupInfo to Containers struct with existing data.
		// In this case, ctime is just an estimation (current time).
		if errors.Is(err, fs.ErrNotExist) {
			cgroupInfo, container, err = c.cgroupUpdate(cgroupId, path, time.Now(), true)
			if err != nil {
				logger.Errorw("cgroupUpdate", "error", err)
			}
		}

		return cgroupInfo, container
	}

	c.lock.RLock()
	defer c.lock.RUnlock()
	cgroupInfo := c.cgroupsMap[uint32(cgroupId)]
	container := c.containerMap[cgroupInfo.ContainerId]

	return cgroupInfo, container
}

// GetLiveContainers provides a list of all existing containers mapped by their cgroup id.
func (c *Manager) GetLiveContainers() map[uint32]Container {
	conts := map[uint32]Container{}
	c.lock.RLock()
	defer c.lock.RUnlock()
	for id, v := range c.cgroupsMap {
		if v.ContainerRoot && v.expiresAt.IsZero() {
			cont := c.containerMap[v.ContainerId]
			conts[id] = cont
		}
	}
	return conts
}

// CgroupExists checks if there is a cgroupInfo data of a given cgroupId.
func (c *Manager) CgroupExists(cgroupId uint64) bool {
	c.lock.RLock()
	_, ok := c.cgroupsMap[uint32(cgroupId)]
	c.lock.RUnlock()
	return ok
}

const (
	containerExisted uint8 = iota + 1
	containerCreated
	containerStarted
)

// PopulateBpfMap populates the map with all the existing containers so eBPF programs can
// orchestrate new ones with the correct state.
func (c *Manager) PopulateBpfMap(bpfModule *libbpfgo.Module) error {
	containersMap, err := bpfModule.GetMap(c.bpfMapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	c.lock.RLock()
	for cgroupIdLsb, info := range c.cgroupsMap {
		if info.ContainerRoot {
			state := containerExisted
			err = containersMap.Update(unsafe.Pointer(&cgroupIdLsb), unsafe.Pointer(&state))
		}
	}
	c.lock.RUnlock()

	return errfmt.WrapError(err)
}

// RemoveFromBPFMap removes a container from the map so eBPF programs can stop tracking it.
func (c *Manager) RemoveFromBPFMap(bpfModule *libbpfgo.Module, cgroupId uint64, hierarchyID uint32) error {
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
	err = containersMap.DeleteKey(unsafe.Pointer(&cgroupIdLsb))

	// ignores the error if the cgroup was already deleted
	if errors.Is(err, syscall.ENOENT) {
		logger.Debugw("cgroup already deleted", "error", err)
		return nil
	}

	return err
}

//
// "Pure" Container Helpers
//

func (c *Manager) AddContainer(cont Container) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.addContainer(cont)
}

func (c *Manager) addContainer(cont Container) error {
	c.containerMap[cont.ContainerId] = cont
	return nil
}

func (c *Manager) RemoveContainer(cont Container) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.containerMap, cont.ContainerId)
	return nil
}

func (c *Manager) GetContainer(containerId string) (Container, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	cont, ok := c.containerMap[containerId]

	if !ok {
		return cont, errfmt.Errorf("no container with id %s", containerId)
	}
	return cont, nil
}
