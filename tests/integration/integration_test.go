package integration

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
)

func Test_InitNamespacesEvent(t *testing.T) {
	t.Parallel()

	assureIsRoot(t)

	procNamespaces := [...]string{"mnt", "cgroup", "pid", "pid_for_children", "time", "time_for_children", "user", "ipc", "net", "uts"}
	evts := events.InitNamespacesEvent()
	initNamespaces := make(map[string]uint32)

	for _, arg := range evts.Args {
		namespaceVale, ok := arg.Value.(uint32)
		assert.Truef(t, ok, "Value of namespace %s is not valid: %v", arg.Name, arg.Value)
		initNamespaces[arg.Name] = namespaceVale
	}

	for _, namespace := range procNamespaces {
		assert.Contains(t, initNamespaces, namespace)
		assert.NotZero(t, initNamespaces[namespace])
	}
}
