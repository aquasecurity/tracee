package containers

import (
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/bucketscache"
	"github.com/aquasecurity/tracee/pkg/capabilities"
)

func TestPathResolver_ResolveAbsolutePath(t *testing.T) {
	t.Parallel()

	t.Run("Mountns cache tests", func(t *testing.T) {
		type process struct {
			pid   uint32
			alive bool
		}
		testCases := []struct {
			Name          string
			nsProcesses   []process
			ExpectedError bool
		}{
			{
				Name: "Existing single process",
				nsProcesses: []process{
					{pid: 1, alive: true},
				},
				ExpectedError: false,
			},
			{
				Name: "Existing single process and dead children",
				nsProcesses: []process{
					{pid: 1, alive: true},
					{pid: 2, alive: false},
					{pid: 3, alive: false},
				},
				ExpectedError: false,
			},
			{
				Name: "Existing single child process",
				nsProcesses: []process{
					{pid: 1, alive: false},
					{pid: 2, alive: true},
					{pid: 1, alive: false},
				},
				ExpectedError: false,
			},
			{
				Name: "No living processes",
				nsProcesses: []process{
					{pid: 1, alive: false},
					{pid: 2, alive: false},
					{pid: 1, alive: false},
				},
				ExpectedError: true,
			},
			{
				Name:          "No processes in NS",
				nsProcesses:   []process{},
				ExpectedError: true,
			},
		}
		testMntNS := 1
		testFilePath := "/tmp/tmp.so"

		err := capabilities.Initialize(
			capabilities.Config{
				Bypass: true,
			},
		) // initialize capabilities
		assert.NoError(t, err)

		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.Name, func(t *testing.T) {
				t.Parallel()

				// Initialize a mock for the os.Stat function
				mfs := fstest.MapFS{}
				bucket := bucketscache.BucketsCache{}
				bucket.Init(20)
				for _, p := range testCase.nsProcesses {
					if p.alive {
						mfs[fmt.Sprintf("proc/%d/root/%s", p.pid, testFilePath)] = &fstest.MapFile{}
						bucket.AddBucketItem(uint32(testMntNS), p.pid)
					}
				}

				pres := InitContainerPathResolver(&bucket)
				pres.fs = mfs
				_, err := pres.GetHostAbsPath(testFilePath, testMntNS)
				if testCase.ExpectedError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("Path tests", func(t *testing.T) {
		testCases := []struct {
			name          string
			path          string
			pathExist     bool
			expectedError bool
		}{
			{
				name:          "Absolute path",
				path:          "/tmp/tmp.so",
				pathExist:     true,
				expectedError: false,
			},
			{
				name:          "Relative path",
				path:          "./temp.so",
				pathExist:     true,
				expectedError: true,
			},
			{
				name:          "Empty path",
				path:          "",
				pathExist:     true,
				expectedError: true,
			},
			{
				name:          "Illegal path",
				path:          "/tmp/tmp.so",
				pathExist:     false,
				expectedError: true,
			},
		}
		testMntNS := 1
		testPID := 1
		bucket := bucketscache.BucketsCache{}
		bucket.Init(20)
		bucket.AddBucketItem(uint32(testMntNS), 1)
		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				// Initialize a mock for the os.Stat function
				mfs := fstest.MapFS{}
				if testCase.pathExist {
					mfs[fmt.Sprintf("proc/%d/root/%s", testPID, testCase.path)] = &fstest.MapFile{}
				}

				pres := InitContainerPathResolver(&bucket)
				pres.fs = mfs
				_, err := pres.GetHostAbsPath(testCase.path, testMntNS)
				if testCase.expectedError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}
