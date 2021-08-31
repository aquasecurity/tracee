package tracee

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func getProcNamespaces() []string {
	return []string{"mnt", "cgroup", "pid", "pid_for_children", "time", "time_for_children", "user", "ipc", "net", "uts"}
}

func TestFetchInitNamespaces(t *testing.T) {
	initNamespacesArgs := getInitNamespaceArguments()
	initNamespaces := make(map[string]uint32)
	for _, arg := range initNamespacesArgs {
		namespaceVale, ok := arg.Value.(uint32)
		assert.Truef(t, ok, "Value of namespace %s is not valid: %v", arg.Name, arg.Value)
		initNamespaces[arg.Name] = namespaceVale
	}
	for _, namespace := range getProcNamespaces() {
		assert.Contains(t, initNamespaces, namespace)
		assert.NotZero(t, initNamespaces[namespace])
	}
}
