// Invoked tracee-ebpf events from user mode
//
// This utility can be useful to generate information needed by signatures that
// is not provided by normal events in the kernel.
//
// Because the events in the kernel are invoked by other programs behavior, we
// cannot anticipate which events will be invoked and as a result what
// information will be extracted.
//
// This is critical because tracee-rules is independent, and doesn't have to run
// on the same machine as tracee-ebpf. This means that tracee-rules might lack
// basic information of the operating machine needed for some signatures.
//
// By creating user mode events this information could be intentionally
// collected and passed to tracee-ebpf afterwards.
package events

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events/pipeline"
	"github.com/aquasecurity/tracee/pkg/logger"
	traceeversion "github.com/aquasecurity/tracee/pkg/version"
	"github.com/aquasecurity/tracee/types/trace"
)

const InitProcNsDir = "/proc/1/ns"

// InitNamespacesEvent collect the init process namespaces and create event from
// them.
func InitNamespacesEvent() pipeline.Event {
	initNamespacesDef := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := getInitNamespaceArguments()

	initNamespacesEvent := pipeline.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee-ebpf",
		EventID:     int(InitNamespaces),
		EventName:   initNamespacesDef.GetName(),
		ArgsNum:     len(initNamespacesArgs),
		Args:        initNamespacesArgs,
	}

	return initNamespacesEvent
}

// TraceeInfoEvent exports data related to Tracee's initialization
func TraceeInfoEvent(bootTime uint64, startTime uint64) pipeline.Event {
	def := Core.GetDefinitionByID(TraceeInfo)
	fields := def.GetFields()
	args := []trace.Argument{
		{ArgMeta: fields[0].ArgMeta, Value: bootTime},
		{ArgMeta: fields[1].ArgMeta, Value: startTime},
		{ArgMeta: fields[2].ArgMeta, Value: traceeversion.GetVersion()},
	}

	traceeInfoEvent := pipeline.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee",
		EventID:     int(def.GetID()),
		EventName:   def.GetName(),
		ArgsNum:     len(args),
		Args:        args,
	}

	return traceeInfoEvent
}

// getInitNamespaceArguments fetches the namespaces of the init process and
// parse them into event arguments.
func getInitNamespaceArguments() []trace.Argument {
	initNamespaces := fetchInitNamespaces()
	eventDefinition := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := make([]trace.Argument, len(eventDefinition.GetFields()))

	fields := eventDefinition.GetFields()

	for i, arg := range initNamespacesArgs {
		arg.ArgMeta = fields[i].ArgMeta
		arg.Value = initNamespaces[arg.Name]
		initNamespacesArgs[i] = arg
	}

	return initNamespacesArgs
}

// fetchInitNamespaces fetches the namespaces values from the /proc/1/ns
// directory
func fetchInitNamespaces() map[string]uint32 {
	var err error
	var namespacesLinks []os.DirEntry

	initNamespacesMap := make(map[string]uint32)
	namespaceValueReg := regexp.MustCompile(":[[[:digit:]]*]")

	namespacesLinks, err = os.ReadDir(InitProcNsDir)
	if err != nil {
		logger.Errorw("fetching init namespaces", "error", err)
	}
	for _, namespaceLink := range namespacesLinks {
		linkString, _ := os.Readlink(filepath.Join(InitProcNsDir, namespaceLink.Name()))
		trim := strings.Trim(namespaceValueReg.FindString(linkString), "[]:")
		namespaceNumber, _ := strconv.ParseUint(trim, 10, 32)
		initNamespacesMap[namespaceLink.Name()] = uint32(namespaceNumber)
	}

	return initNamespacesMap
}

// ExistingContainersEvents returns a list of events for each existing container
func ExistingContainersEvents(cts *containers.Manager, enrichDisabled bool) []pipeline.Event {
	var events []pipeline.Event

	def := Core.GetDefinitionByID(ExistingContainer)
	existingContainers := cts.GetLiveContainers()
	for id, container := range existingContainers {
		cgroupId := uint64(id)
		cRuntime := container.Runtime.String()
		containerId := container.ContainerId
		ctime := container.CreatedAt.UnixNano()
		container := containers.Container{}
		if !enrichDisabled {
			container, _ = cts.EnrichCgroupInfo(cgroupId)
		}
		fields := def.GetFields()
		args := []trace.Argument{
			{ArgMeta: fields[0].ArgMeta, Value: cRuntime},
			{ArgMeta: fields[1].ArgMeta, Value: containerId},
			{ArgMeta: fields[2].ArgMeta, Value: ctime},
			{ArgMeta: fields[3].ArgMeta, Value: container.Image},
			{ArgMeta: fields[4].ArgMeta, Value: container.ImageDigest},
			{ArgMeta: fields[5].ArgMeta, Value: container.Name},
			{ArgMeta: fields[6].ArgMeta, Value: container.Pod.Name},
			{ArgMeta: fields[7].ArgMeta, Value: container.Pod.Namespace},
			{ArgMeta: fields[8].ArgMeta, Value: container.Pod.UID},
			{ArgMeta: fields[9].ArgMeta, Value: container.Pod.Sandbox},
		}
		existingContainerEvent := pipeline.Event{
			Timestamp:   int(time.Now().UnixNano()),
			ProcessName: "tracee-ebpf",
			EventID:     int(ExistingContainer),
			EventName:   def.GetName(),
			ArgsNum:     len(args),
			Args:        args,
		}
		events = append(events, existingContainerEvent)
	}

	return events
}
