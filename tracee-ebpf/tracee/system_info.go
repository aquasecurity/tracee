package tracee

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const INIT_PROC_NS_DIR = "/proc/1/ns"

// FetchSystemInfo Fetch info from the system that might be significant for later use or for signatures.
func FetchSystemInfo() map[string]interface{} {
	systemInfo := make(map[string]interface{})
	systemInfo["initNamespaces"] = fetchInitNamespaces()
	return systemInfo
}

func fetchInitNamespaces() map[string]int {
	initNamespacesMap := make(map[string]int)
	namespacesLinks, _ := ioutil.ReadDir(INIT_PROC_NS_DIR)
	for _, namespaceLink := range namespacesLinks {
		namespaceString, _ := os.Readlink(filepath.Join(INIT_PROC_NS_DIR, namespaceLink.Name()))
		namespaceNumber, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(namespaceString, ":["), ":]"))
		initNamespacesMap[namespaceString] = namespaceNumber
	}
	return initNamespacesMap
}
