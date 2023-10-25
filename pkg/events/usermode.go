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
	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

const InitProcNsDir = "/proc/1/ns"

// InitNamespacesEvent collect the init process namespaces and create event from
// them.
func InitNamespacesEvent() trace.Event {
	initNamespacesDef := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := getInitNamespaceArguments()

	initNamespacesEvent := trace.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee-ebpf",
		EventID:     int(InitNamespaces),
		EventName:   initNamespacesDef.GetName(),
		ArgsNum:     len(initNamespacesArgs),
		Args:        initNamespacesArgs,
	}

	return initNamespacesEvent
}

// getInitNamespaceArguments fetches the namespaces of the init process and
// parse them into event arguments.
func getInitNamespaceArguments() []trace.Argument {
	initNamespaces := fetchInitNamespaces()
	eventDefinition := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := make([]trace.Argument, len(eventDefinition.GetParams()))

	params := eventDefinition.GetParams()

	for i, arg := range initNamespacesArgs {
		arg.ArgMeta = params[i]
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
func ExistingContainersEvents(cts *containers.Containers, enrichDisabled bool) []trace.Event {
	var events []trace.Event

	def := Core.GetDefinitionByID(ExistingContainer)

	for id, info := range cts.GetContainers() {
		container := runtime.ContainerMetadata{}
		if !enrichDisabled {
			container, _ = cts.EnrichCgroupInfo(uint64(id))
		}
		params := def.GetParams()
		args := []trace.Argument{
			{ArgMeta: params[0], Value: info.Runtime.String()},
			{ArgMeta: params[1], Value: info.Container.ContainerId},
			{ArgMeta: params[2], Value: info.Ctime.UnixNano()},
			{ArgMeta: params[3], Value: container.Image},
			{ArgMeta: params[3], Value: container.ImageDigest},
			{ArgMeta: params[4], Value: container.Name},
			{ArgMeta: params[5], Value: container.Pod.Name},
			{ArgMeta: params[6], Value: container.Pod.Namespace},
			{ArgMeta: params[7], Value: container.Pod.UID},
			{ArgMeta: params[8], Value: container.Pod.Sandbox},
		}
		existingContainerEvent := trace.Event{
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
