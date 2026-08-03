package integration

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

func Test_InitNamespacesEvent(t *testing.T) {
	t.Parallel()

	testutils.AssureIsRoot(t)

	// Mirrors requiredInitNamespaces in pkg/events/usermode.go: present and
	// non-zero on every supported kernel.
	requiredNamespaces := [...]string{"cgroup", "ipc", "mnt", "net", "pid", "uts"}
	// May legitimately be 0 (CONFIG_USER_NS=n, pre-5.6 time namespaces).
	optionalNamespaces := [...]string{"pid_for_children", "time", "time_for_children", "user"}

	evts, err := events.InitNamespacesEvent()
	require.NoError(t, err)
	initNamespaces := make(map[string]uint32)

	for _, arg := range evts.Args {
		namespaceVale, ok := arg.Value.(uint32)
		assert.Truef(t, ok, "Value of namespace %s is not valid: %v", arg.Name, arg.Value)
		initNamespaces[arg.Name] = namespaceVale
	}

	for _, namespace := range requiredNamespaces {
		assert.Contains(t, initNamespaces, namespace)
		assert.NotZero(t, initNamespaces[namespace])
	}
	for _, namespace := range optionalNamespaces {
		assert.Contains(t, initNamespaces, namespace)
	}
}
