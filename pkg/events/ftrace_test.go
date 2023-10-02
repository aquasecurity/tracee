package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFtraceFlags(t *testing.T) {
	t.Parallel()

	t.Run("Parse flags", func(t *testing.T) {
		testCases := []struct {
			name          string
			ftraceParts   []string
			index         int
			expectedFlags string
		}{
			{
				name:          "R flag",
				ftraceParts:   []string{"load_elf_phdrs", "(1)", "R", "", "", "", "\ttramp:", "0xffffffffc0241000", "(kprobe_ftrace_handler+0x0/0x1d0)", "->kprobe_ftrace_handler+0x0/0x1d0"},
				index:         2,
				expectedFlags: "R",
			},
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				flags := getFtraceFlags(testCase.ftraceParts, &testCase.index)
				assert.Equal(t, testCase.expectedFlags, flags)
			})
		}
	})
}

func TestGetCallback(t *testing.T) {
	t.Parallel()

	t.Run("Parse callback", func(t *testing.T) {
		testCases := []struct {
			name             string
			ftraceParts      []string
			expectedCallback string
		}{
			{
				name:             "callback",
				ftraceParts:      []string{"(kprobe_ftrace_handler+0x0/0x1d0)", "->kprobe_ftrace_handler+0x0/0x1d0"},
				expectedCallback: "kprobe_ftrace_handler+0x0/0x1d0",
			},
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				flags := getCallback(testCase.ftraceParts)
				assert.Equal(t, testCase.expectedCallback, flags)
			})
		}
	})
}

func TestFetchTrampAndCallback(t *testing.T) {
	t.Parallel()

	t.Run("Parse tramp and callback", func(t *testing.T) {
		testCases := []struct {
			name             string
			ftraceParts      []string
			index            int
			expectedTramp    string
			expectedCallback string
		}{
			{
				name:             "tramp and callback",
				ftraceParts:      []string{"load_elf_phdrs", "(1)", "R", "", "", "", "\ttramp:", "0xffffffffc0241000", "(kprobe_ftrace_handler+0x0/0x1d0)", "->kprobe_ftrace_handler+0x0/0x1d0"},
				index:            1,
				expectedCallback: "kprobe_ftrace_handler+0x0/0x1d0",
				expectedTramp:    "0xffffffffc0241000",
			},
		}

		for _, testCase := range testCases {
			tramp, callback := fetchTrampAndCallback(testCase.ftraceParts, &testCase.index)
			assert.Equal(t, testCase.expectedCallback, callback)
			assert.Equal(t, testCase.expectedTramp, tramp)
		}
	})
}

func TestSplitCallback(t *testing.T) {
	t.Parallel()

	t.Run("Split callback", func(t *testing.T) {
		testCases := []struct {
			name             string
			callback         string
			expectedFuncName string
			expectedOffset   int64
			expectedOwner    string
		}{
			{
				name:             "Callback",
				callback:         "some_func+0x1/0x10 [rootkit]",
				expectedFuncName: "some_func",
				expectedOffset:   1,
				expectedOwner:    "rootkit",
			},
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				funcName, offset, owner := splitCallback(testCase.callback)
				assert.Equal(t, testCase.expectedFuncName, funcName)
				assert.Equal(t, testCase.expectedOffset, offset)
				assert.Equal(t, testCase.expectedOwner, owner)
			})
		}
	})
}
