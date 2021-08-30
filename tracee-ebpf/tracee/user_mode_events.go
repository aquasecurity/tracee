// Invoked tracee-ebpf events from user mode
// This utility can prove itself useful to generate information needed by signatures that is not provided by normal
// events in the kernel.
// Because the events in the kernel are invoked by other programs behavior, we cannot anticipate which events will be
// invoked and as a result what information will be extracted.
// This is critical because tracee-rules is independent, and doesn't have to run on the same machine as tracee-ebpf.
// This means that tracee-rules might lack basic information of the operating machine needed for some signatures.
// By creating user mode events this information could be intentionally collected and passed to tracee-ebpf afterwards.
package tracee

import (
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const InitProcNsDir = "/proc/1/ns"

const InitNamespacesKey = "initNamespaces"

// CreateSystemInfoEvent collect information of the running machine and create an event that includes this information.
func CreateSystemInfoEvent() (external.Event, error) {
	systemInfoArgs := fetchSystemInfo()
	systemInfoEvent := external.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee-ebpf",
		EventID:     int(SystemInfoEventID),
		EventName:   EventsIDToEvent[SystemInfoEventID].Name,
		ArgsNum:     len(systemInfoArgs),
		Args:        systemInfoArgs,
	}
	return systemInfoEvent, nil
}

// fetchSystemInfo Fetch info from the system that might be significant for later use or for signatures.
func fetchSystemInfo() []external.Argument {
	systemInfo := make([]external.Argument, 1)
	systemInfo[0] = external.Argument{
		ArgMeta: external.ArgMeta{Name: "initNamespaces", Type: "map[string]int"},
		Value:   fetchInitNamespaces(),
	}
	return systemInfo
}

func fetchInitNamespaces() map[string]int {
	initNamespacesMap := make(map[string]int)
	namespaceValueReg := regexp.MustCompile(":[[[:digit:]]*]")
	namespacesLinks, _ := ioutil.ReadDir(InitProcNsDir)
	for _, namespaceLink := range namespacesLinks {
		linkString, _ := os.Readlink(filepath.Join(InitProcNsDir, namespaceLink.Name()))
		trim := strings.Trim(namespaceValueReg.FindString(linkString), "[]:")
		namespaceNumber, _ := strconv.Atoi(trim)
		initNamespacesMap[namespaceLink.Name()] = namespaceNumber
	}
	return initNamespacesMap
}
