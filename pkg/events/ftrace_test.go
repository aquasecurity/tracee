package events

import (
	"fmt"
	"strings"
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
				assert.Equal(t, testCase.expectedFlags, flags.String())
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

// TestParseFtraceHook locks the end-to-end parsing behavior of a single
// enabled_functions line (as fed by checkFtraceHooks, i.e. after tabs are
// turned into spaces) across every callback shape the parser handles.
func TestParseFtraceHook(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		rawLine   string
		expectErr bool
		expected  reportedFtraceHook
	}{
		{
			name:    "tramp form",
			rawLine: "load_elf_phdrs (1) R \ttramp: 0xffffffffc0241000 (kprobe_ftrace_handler+0x0/0x1d0) ->kprobe_ftrace_handler+0x0/0x1d0",
			expected: reportedFtraceHook{
				symbol:       "load_elf_phdrs",
				count:        1,
				flags:        ftraceFlagRegs,
				trampoline:   "0xffffffffc0241000",
				callbackFunc: "kprobe_ftrace_handler",
			},
		},
		{
			name:    "ops form",
			rawLine: "tcp_sendmsg (1) R \tops: 0xffffffffc0500000 (bpf_kprobe_handler+0x0/0x80)",
			expected: reportedFtraceHook{
				symbol:       "tcp_sendmsg",
				count:        1,
				flags:        ftraceFlagRegs,
				callbackFunc: "bpf_kprobe_handler",
			},
		},
		{
			name:    "arrow form",
			rawLine: "sys_open (1) R ->security_file_open+0x0/0x90",
			expected: reportedFtraceHook{
				symbol:       "sys_open",
				count:        1,
				flags:        ftraceFlagRegs,
				callbackFunc: "security_file_open",
			},
		},
		{
			name:    "callback with owner",
			rawLine: "evil_sym (1) R \ttramp: 0xffffffffc0637000 (some_func+0x1/0x10 [rootkit])",
			expected: reportedFtraceHook{
				symbol:         "evil_sym",
				count:          1,
				flags:          ftraceFlagRegs,
				trampoline:     "0xffffffffc0637000",
				callbackFunc:   "some_func",
				callbackOffset: 1,
				callbackOwner:  "rootkit",
			},
		},
		{
			name:    "address only callback",
			rawLine: "mystery (1) R \ttramp: 0xffffffffc0241000 (0xffffffffc0637000)",
			expected: reportedFtraceHook{
				symbol:       "mystery",
				count:        1,
				flags:        ftraceFlagRegs,
				trampoline:   "0xffffffffc0241000",
				callbackFunc: "0xffffffffc0637000",
			},
		},
		{
			name:    "multiple flags including direct",
			rawLine: "vfs_write (3) R I D ->callback_func+0x0/0x0",
			expected: reportedFtraceHook{
				symbol:       "vfs_write",
				count:        3,
				flags:        ftraceFlagRegs | ftraceFlagIPModify | ftraceFlagDirect,
				callbackFunc: "callback_func",
			},
		},
		{
			name:      "too few fields",
			rawLine:   "incomplete (1)",
			expectErr: true,
		},
		{
			name:      "non-numeric count",
			rawLine:   "sym (x) R ->cb+0x0/0x0",
			expectErr: true,
		},
		{
			name:      "callback offset exceeds int32",
			rawLine:   "sym (1) R ->cb+0x100000000/0x100000001",
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Mirror checkFtraceHooks: tabs are normalized to spaces before parsing.
			line := strings.ReplaceAll(testCase.rawLine, "\t", " ")
			hook, err := parseFtraceHook(line)

			if testCase.expectErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, hook)
		})
	}
}

// TestFtraceFlagsString locks the textual rendering of the flag bitmask: it must
// emit characters in the kernel's fixed R,I,D,O,M order regardless of set order,
// so the reported "flags" argument matches the original enabled_functions column.
func TestFtraceFlagsString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		flags    ftraceFlags
		expected string
	}{
		{name: "none", flags: 0, expected: ""},
		{name: "single R", flags: ftraceFlagRegs, expected: "R"},
		{name: "single M", flags: ftraceFlagModified, expected: "M"},
		{name: "RID", flags: ftraceFlagRegs | ftraceFlagIPModify | ftraceFlagDirect, expected: "RID"},
		{name: "all", flags: ftraceFlagRegs | ftraceFlagIPModify | ftraceFlagDirect | ftraceFlagCallOps | ftraceFlagModified, expected: "RIDOM"},
		{name: "order independent", flags: ftraceFlagModified | ftraceFlagRegs | ftraceFlagDirect, expected: "RDM"},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected, testCase.flags.String())
		})
	}
}

// TestParseKprobeFtraceCounts locks the per-symbol counting and deduplication
// semantics: only [FTRACE] kprobes count, the first address per (symbol,hookType)
// counts, and subsequent lines only count when they repeat that same address.
func TestParseKprobeFtraceCounts(t *testing.T) {
	t.Parallel()

	data := []byte(strings.Join([]string{
		"ffffffff9fd44d20  k  load_elf_phdrs+0x0    [FTRACE]",
		"ffffffff9fd47b60  k  load_elf_phdrs+0x0    [FTRACE]", // different addr, same symbol+type -> not counted again
		"aaaaaaaaaaaaaaaa  k  vfs_read+0x0    [FTRACE]",
		"aaaaaaaaaaaaaaaa  k  vfs_read+0x0    [FTRACE]", // same addr -> counted again
		"bbbbbbbbbbbbbbbb  k  tcp_v4_connect+0x0    [FTRACE]",
		"cccccccccccccccc  r  tcp_v4_connect+0x0    [FTRACE]", // different hook type -> counted
		"c015d71a  k  do_exit+0x0",                            // not ftrace based -> skipped
		"dddddddddddddddd  k  weirdsym    [FTRACE]",           // no '+' offset -> skipped
		"eeee k", // too few fields -> skipped
		"",       // empty line -> skipped
	}, "\n"))

	counts := parseKprobeFtraceCounts(data)

	assert.Equal(t, 1, counts["load_elf_phdrs"])
	assert.Equal(t, 2, counts["vfs_read"])
	assert.Equal(t, 2, counts["tcp_v4_connect"])

	_, hasDoExit := counts["do_exit"]
	assert.False(t, hasDoExit, "non-ftrace kprobe must not be counted")

	_, hasWeird := counts["weirdsym"]
	assert.False(t, hasWeird, "malformed symbol+offset must be skipped")
}

// TestReportedFtraceHookDetachAndEquality locks the dedup-cache snapshot
// behavior: snapshots are comparable with == and detach preserves all values
// (it only relocates the strings off the source buffer).
func TestReportedFtraceHookDetachAndEquality(t *testing.T) {
	t.Parallel()

	line := strings.ReplaceAll("evil_sym (1) R \ttramp: 0xffffffffc0637000 (some_func+0x1/0x10 [rootkit])", "\t", " ")
	h1, err := parseFtraceHook(line)
	assert.NoError(t, err)
	h2, err := parseFtraceHook(line)
	assert.NoError(t, err)
	assert.True(t, h1 == h2, "identical lines must produce equal snapshots")

	detached := h1.detach()
	assert.True(t, h1 == detached, "detach must preserve all field values")

	// A changed callback must break equality (drives re-reporting).
	changed := h1
	changed.callbackFunc = "different_func"
	assert.False(t, h1 == changed, "a changed callback must not compare equal")
}

func BenchmarkParseFtraceHook(b *testing.B) {
	line := strings.ReplaceAll("load_elf_phdrs (1) R \ttramp: 0xffffffffc0241000 (kprobe_ftrace_handler+0x0/0x1d0) ->kprobe_ftrace_handler+0x0/0x1d0", "\t", " ")

	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseFtraceHook(line); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseKprobeFtraceCounts(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, "ffffffff9fd4%04x  k  sym_%d+0x0    [FTRACE]\n", i, i)
	}
	data := []byte(sb.String())

	b.ReportAllocs()
	for b.Loop() {
		_ = parseKprobeFtraceCounts(data)
	}
}
