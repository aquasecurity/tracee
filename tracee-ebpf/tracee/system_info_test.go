package tracee

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func getProcNamespaces() []string {
	return []string{"mnt", "cgroup", "pid", "time", "user", "ipc", "net", "uts"}
}

func TestFetchSystemInfo(t *testing.T) {
	systemInfo := FetchSystemInfo()
	require.Contains(t, systemInfo, INIT_NAMESPACES_KEY)
	initNamespaces := systemInfo[INIT_NAMESPACES_KEY]
	for _, namespace := range getProcNamespaces() {
		assert.Contains(t, initNamespaces, namespace)
	}
}
