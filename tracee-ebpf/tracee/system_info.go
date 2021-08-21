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

const SYSTEM_INFO_FILE_NAME = "system_info.json"

const INIT_PROC_NS_DIR = "/proc/1/ns"

const INIT_NAMESPACES_KEY = "initNamespaces"

// FetchSystemInfo Fetch info from the system that might be significant for later use or for signatures.
func FetchSystemInfo() []external.Argument {
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
	namespacesLinks, _ := ioutil.ReadDir(INIT_PROC_NS_DIR)
	for _, namespaceLink := range namespacesLinks {
		linkString, _ := os.Readlink(filepath.Join(INIT_PROC_NS_DIR, namespaceLink.Name()))
		trim := strings.Trim(namespaceValueReg.FindString(linkString), "[]:")
		namespaceNumber, _ := strconv.Atoi(trim)
		initNamespacesMap[namespaceLink.Name()] = namespaceNumber
	}
	return initNamespacesMap
}

func InvokeSystemInfoEvent(printer eventPrinter) error {
	systemInfoArgs := FetchSystemInfo()
	systemInfoEvent := external.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee-ebpf",
		EventID:     0,
		EventName:   "System Info",
		ArgsNum:     len(systemInfoArgs),
		Args:        systemInfoArgs,
	}
	printer.Print(systemInfoEvent)
	return nil
}
