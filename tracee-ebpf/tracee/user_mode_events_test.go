package tracee

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func getProcNamespaces() []string {
	return []string{"mnt", "cgroup", "pid", "time", "user", "ipc", "net", "uts"}
}

func TestFetchInitNamespaces(t *testing.T) {
	initNamespacesArgs := getInitNamespaceArguments()
	initNamespaces := make(map[string]int)
	for _, arg := range initNamespacesArgs {
		initNamespaces[arg.Name] = arg.Value.(int)
	}
	for _, namespace := range getProcNamespaces() {
		assert.Contains(t, initNamespaces, namespace)
	}
}
