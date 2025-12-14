package process

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

func TestProcessTree_DataStoreInterface(t *testing.T) {
	// Create a process tree for testing
	pt, err := NewProcessTree(context.Background(), ProcTreeConfig{
		Source:           SourceNone,
		ProcessCacheSize: 100,
		ThreadCacheSize:  100,
	})
	require.NoError(t, err)

	t.Run("Name", func(t *testing.T) {
		name := pt.Name()
		assert.Equal(t, "process", name)
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := pt.GetHealth()
		require.NotNil(t, health)
		assert.Equal(t, datastores.HealthHealthy, health.Status)
		assert.Empty(t, health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := pt.GetMetrics()
		require.NotNil(t, metrics)
		assert.GreaterOrEqual(t, metrics.ItemCount, int64(0))
	})

	t.Run("GetProcess_NotFound", func(t *testing.T) {
		info, found := pt.GetProcess(999999)
		assert.False(t, found)
		assert.Nil(t, info)
	})

	t.Run("GetChildProcesses_NotFound", func(t *testing.T) {
		children, err := pt.GetChildProcesses(999999)
		assert.NoError(t, err)
		assert.Empty(t, children)
	})

	t.Run("LastAccessTracking", func(t *testing.T) {
		// Get initial metrics
		metrics1 := pt.GetMetrics()
		initialLastAccess := metrics1.LastAccess

		// Sleep briefly to ensure timestamp difference
		time.Sleep(10 * time.Millisecond)

		// Access the datastore
		_, _ = pt.GetProcess(123)

		// Check that LastAccess was updated
		metrics2 := pt.GetMetrics()
		assert.True(t, metrics2.LastAccess.After(initialLastAccess),
			"LastAccess should be updated after GetProcess call")
	})
}

func TestProcessStore_GetAncestry(t *testing.T) {
	ctx := context.Background()
	pt, err := NewProcessTree(ctx, ProcTreeConfig{
		Source:           SourceNone,
		ProcessCacheSize: 100,
		ThreadCacheSize:  100,
	})
	require.NoError(t, err)

	// Create a process tree: init -> bash -> python
	// init (hash: 100)
	initProc := pt.GetOrCreateProcessByHash(100)
	initFeed := &TaskInfoFeed{
		Pid:    1,
		NsPid:  1,
		PPid:   0,
		NsPPid: 0,
		Name:   "init",
	}
	initProc.GetInfo().SetFeed(initFeed)
	initProc.SetParentHash(0) // No parent

	// bash (hash: 200, parent: 100)
	bashProc := pt.GetOrCreateProcessByHash(200)
	bashFeed := &TaskInfoFeed{
		Pid:    1000,
		NsPid:  1,
		PPid:   1,
		NsPPid: 1,
		Name:   "bash",
	}
	bashProc.GetInfo().SetFeed(bashFeed)
	bashProc.SetParentHash(100)

	// python (hash: 300, parent: 200)
	pythonProc := pt.GetOrCreateProcessByHash(300)
	pythonFeed := &TaskInfoFeed{
		Pid:    2000,
		NsPid:  100,
		PPid:   1000,
		NsPPid: 1,
		Name:   "python",
	}
	pythonProc.GetInfo().SetFeed(pythonFeed)
	pythonProc.SetParentHash(200)

	t.Run("get ancestry with maxDepth 5", func(t *testing.T) {
		ancestry, err := pt.GetAncestry(uint32(300), 5)
		assert.NoError(t, err)
		assert.Len(t, ancestry, 3) // python -> bash -> init

		// Python process
		assert.Equal(t, uint32(300), ancestry[0].UniqueId)
		assert.Equal(t, "python", ancestry[0].Name)
		assert.NotZero(t, ancestry[0].HostPid)
		assert.NotZero(t, ancestry[0].Pid)
		assert.Equal(t, uint32(200), ancestry[0].ParentUniqueId)

		// Bash process
		assert.Equal(t, uint32(200), ancestry[1].UniqueId)
		assert.Equal(t, "bash", ancestry[1].Name)
		assert.Equal(t, uint32(100), ancestry[1].ParentUniqueId)

		// Init process
		assert.Equal(t, uint32(100), ancestry[2].UniqueId)
		assert.Equal(t, "init", ancestry[2].Name)
		assert.Equal(t, uint32(0), ancestry[2].ParentUniqueId) // Init has no parent
	})

	t.Run("get ancestry with maxDepth 1", func(t *testing.T) {
		ancestry, err := pt.GetAncestry(uint32(300), 1)
		assert.NoError(t, err)
		assert.Len(t, ancestry, 1) // Only python itself
		assert.Equal(t, "python", ancestry[0].Name)
	})

	t.Run("get ancestry for non-existent process", func(t *testing.T) {
		ancestry, err := pt.GetAncestry(uint32(999), 5)
		assert.NoError(t, err)
		assert.Len(t, ancestry, 0) // Not found
	})

	t.Run("get ancestry with maxDepth 0", func(t *testing.T) {
		ancestry, err := pt.GetAncestry(uint32(300), 0)
		assert.NoError(t, err)
		assert.Len(t, ancestry, 0) // Zero depth returns empty
	})

	t.Run("process with exit time", func(t *testing.T) {
		// Create process and mark as exited
		proc := pt.GetOrCreateProcessByHash(999)
		feed := &TaskInfoFeed{
			Pid:        9999,
			NsPid:      9999,
			PPid:       1,
			NsPPid:     1,
			Name:       "exited",
			ExitTimeNS: uint64(time.Now().UnixNano()),
		}
		proc.GetInfo().SetFeed(feed)

		info, ok := pt.GetProcess(uint32(999))
		require.True(t, ok)
		assert.NotZero(t, info.ExitTime, "ExitTime should be populated")
	})
}
