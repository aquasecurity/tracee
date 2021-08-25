package userevents

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func getProcNamespaces() []string {
	return []string{"mnt", "cgroup", "pid", "time", "user", "ipc", "net", "uts"}
}

func TestFetchSystemInfo(t *testing.T) {
	systemInfoArgs := fetchSystemInfo()
	systemInfo := make(map[string]int)
	for _, arg := range systemInfoArgs {
		if arg.Name == InitNamespacesKey {
			systemInfo = arg.Value.(map[string]int)
		}
	}
	require.True(t, systemInfo != nil)
	initNamespaces := systemInfo
	for _, namespace := range getProcNamespaces() {
		assert.Contains(t, initNamespaces, namespace)
	}
}
