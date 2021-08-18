package tracee

import (
	"encoding/json"
	"fmt"
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

// SaveSystemInfo Writes a map that represent the system info fetched from the machine to output file in json format.
func SaveSystemInfo(systemInfo map[string]interface{}, outDir string) error {
	systemInfoFile, err := os.Create(filepath.Join(outDir, SYSTEM_INFO_FILE_NAME))
	if err != nil {
		return fmt.Errorf("couldn't create system info dump file: %v", err)
	}
	encoder := json.NewEncoder(systemInfoFile)
	err = encoder.Encode(systemInfo)
	if err != nil {
		return fmt.Errorf("couldn't write system info to the output fil: %v", err)
	}
	return nil
}

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

func (t *Tracee) InvokeSystemInfoEvent() error {
	systemInfoEvent := external.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "System Info",
		HostName:    "",
		ContainerID: "",
		EventID:     0,
		EventName:   "System Info",
		ArgsNum:     0,
		Args:        FetchSystemInfo(),
	}
	t.printer.Print(systemInfoEvent)
	return nil
}
