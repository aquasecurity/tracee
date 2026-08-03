// Invoked tracee events from user mode
//
// This utility can be useful to generate information needed by signatures that
// is not provided by normal events in the kernel.
//
// Because the events in the kernel are invoked by other programs behavior, we
// cannot anticipate which events will be invoked and as a result what
// information will be extracted.
//
// This is critical because signatures can be evaluated independently, and don't
// have to run on the same machine as tracee. This means signature evaluation might
// lack basic information of the operating machine needed for some signatures.
//
// By creating user mode events this information could be intentionally
// collected and passed to tracee afterwards.
package events

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	traceeversion "github.com/aquasecurity/tracee/pkg/version"
	"github.com/aquasecurity/tracee/types/trace"
)

const InitProcNsDir = "/proc/1/ns"

// InitNamespacesEvent collect the init process namespaces and create event from
// them. An error is returned instead of an event with zeroed namespace ids:
// consumers treat the values as authoritative host namespace ids and silently
// misbehave on zeros. Failures are deterministic on a given host (missing
// capability, hardened kernel), so callers should log and drop, not retry.
func InitNamespacesEvent() (trace.Event, error) {
	initNamespacesDef := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs, err := getInitNamespaceArguments()
	if err != nil {
		return trace.Event{}, err
	}

	initNamespacesEvent := trace.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee",
		EventID:     int(InitNamespaces),
		EventName:   initNamespacesDef.GetName(),
		ArgsNum:     len(initNamespacesArgs),
		Args:        initNamespacesArgs,
	}

	return initNamespacesEvent, nil
}

// TraceeInfoEvent exports data related to Tracee's initialization
func TraceeInfoEvent(bootTime uint64, startTime uint64) trace.Event {
	def := Core.GetDefinitionByID(TraceeInfo)
	fields := def.GetFields()
	args := []trace.Argument{
		{ArgMeta: fields[0].ArgMeta, Value: bootTime},
		{ArgMeta: fields[1].ArgMeta, Value: startTime},
		{ArgMeta: fields[2].ArgMeta, Value: traceeversion.GetVersion()},
	}

	traceeInfoEvent := trace.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee",
		EventID:     int(def.GetID()),
		EventName:   def.GetName(),
		ArgsNum:     len(args),
		Args:        args,
	}

	return traceeInfoEvent
}

// requiredInitNamespaces exist on every supported kernel and are the ones
// consumers compare against (switch_task_ns carries mnt/pid/uts/ipc/net/cgroup).
// The remaining fields (user, time namespaces, pid_for_children) may
// legitimately be absent (e.g. CONFIG_USER_NS=n) and default to 0.
var requiredInitNamespaces = map[string]bool{
	"cgroup": true, "ipc": true, "mnt": true, "net": true,
	"pid": true, "uts": true,
}

// getInitNamespaceArguments fetches the namespaces of the init process and
// parse them into event arguments. It errors if any always-present namespace
// could not be resolved, rather than filling the argument with 0.
func getInitNamespaceArguments() ([]trace.Argument, error) {
	initNamespaces, err := fetchInitNamespaces()
	if err != nil {
		return nil, err
	}
	eventDefinition := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := make([]trace.Argument, len(eventDefinition.GetFields()))

	fields := eventDefinition.GetFields()

	for i, arg := range initNamespacesArgs {
		arg.ArgMeta = fields[i].ArgMeta
		value, ok := initNamespaces[arg.Name]
		if !ok && requiredInitNamespaces[arg.Name] {
			return nil, fmt.Errorf("init namespace %s could not be resolved from %s", arg.Name, InitProcNsDir)
		}
		arg.Value = value
		initNamespacesArgs[i] = arg
	}

	return initNamespacesArgs, nil
}

// initNsValueRe matches the bracketed inode of a /proc/*/ns symlink target,
// e.g. "mnt:[4026531840]". (The previous ":[[[:digit:]]*]" form worked too -
// the unescaped '[' was consumed by the character class - but only by
// accident.)
var initNsValueRe = regexp.MustCompile(`:\[[[:digit:]]+\]`)

// parseNamespaceInode extracts the namespace inode from a /proc/*/ns symlink
// target of the form "name:[inode]". Zero is never returned as a value.
func parseNamespaceInode(link string) (uint32, error) {
	trim := strings.Trim(initNsValueRe.FindString(link), "[]:")
	namespaceNumber, err := strconv.ParseUint(trim, 10, 32)
	if err != nil || namespaceNumber == 0 {
		return 0, fmt.Errorf("malformed namespace link %q", link)
	}
	return uint32(namespaceNumber), nil
}

// fetchInitNamespaces fetches the namespaces values from the /proc/1/ns
// directory. Entries that cannot be read or parsed are omitted (never stored
// as 0); an error is returned when nothing could be read at all.
func fetchInitNamespaces() (map[string]uint32, error) {
	initNamespacesMap := make(map[string]uint32)

	namespacesLinks, err := os.ReadDir(InitProcNsDir)
	if err != nil {
		return nil, fmt.Errorf("fetching init namespaces: %w", err)
	}
	for _, namespaceLink := range namespacesLinks {
		linkString, err := os.Readlink(filepath.Join(InitProcNsDir, namespaceLink.Name()))
		if err != nil {
			// per-entry detail only; the caller's aggregate error carries the consequence
			logger.Debugw("reading init namespace link", "namespace", namespaceLink.Name(), "error", err)
			continue
		}
		namespaceNumber, err := parseNamespaceInode(linkString)
		if err != nil {
			logger.Debugw("parsing init namespace link", "namespace", namespaceLink.Name(), "error", err)
			continue
		}
		initNamespacesMap[namespaceLink.Name()] = namespaceNumber
	}
	if len(initNamespacesMap) == 0 {
		return nil, fmt.Errorf("no init namespaces could be read from %s", InitProcNsDir)
	}

	return initNamespacesMap, nil
}

// ExistingContainersEvents returns a list of events for each existing container
func ExistingContainersEvents(cts *container.Manager, enrichmentEnabled bool) []trace.Event {
	var events []trace.Event

	def := Core.GetDefinitionByID(ExistingContainer)
	existingContainers := cts.GetLiveContainers()
	for id, containerInfo := range existingContainers {
		cgroupId := uint64(id)
		cRuntime := containerInfo.Runtime.String()
		containerId := containerInfo.ContainerId
		ctime := containerInfo.CreatedAt.UnixNano()
		enrichedContainer := container.Container{}
		if enrichmentEnabled {
			enrichedContainer, _ = cts.EnrichCgroupInfo(cgroupId)
		}
		fields := def.GetFields()
		args := []trace.Argument{
			{ArgMeta: fields[0].ArgMeta, Value: cRuntime},
			{ArgMeta: fields[1].ArgMeta, Value: containerId},
			{ArgMeta: fields[2].ArgMeta, Value: ctime},
			{ArgMeta: fields[3].ArgMeta, Value: enrichedContainer.Image},
			{ArgMeta: fields[4].ArgMeta, Value: enrichedContainer.ImageDigest},
			{ArgMeta: fields[5].ArgMeta, Value: enrichedContainer.Name},
			{ArgMeta: fields[6].ArgMeta, Value: enrichedContainer.Pod.Name},
			{ArgMeta: fields[7].ArgMeta, Value: enrichedContainer.Pod.Namespace},
			{ArgMeta: fields[8].ArgMeta, Value: enrichedContainer.Pod.UID},
			{ArgMeta: fields[9].ArgMeta, Value: enrichedContainer.Pod.Sandbox},
		}
		existingContainerEvent := trace.Event{
			Timestamp:   int(time.Now().UnixNano()),
			ProcessName: "tracee",
			EventID:     int(ExistingContainer),
			EventName:   def.GetName(),
			ArgsNum:     len(args),
			Args:        args,
		}
		events = append(events, existingContainerEvent)
	}

	return events
}
