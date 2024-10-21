package proc

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

func createMockStatusFile() (string, error) {
	dirPath := "/tmp/tracee-test"
	filePath, err := tests.GenerateTimestampFileName(dirPath, "status")
	if err != nil {
		return "", err
	}

	err = os.MkdirAll(dirPath, 0755)
	if err != nil {
		return "", err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	content := `
Name:   Utility Process
Umask:  0022
State:  R (running)
Tgid:   216447
Ngid:   0
Pid:    216447
PPid:   3994523
TracerPid:      0
Uid:    1000    1000    1000    1000
Gid:    1000    1000    1000    1000
FDSize: 128
Groups: 3 90 98 108 955 959 986 991 998 1000 
NStgid: 216447
NSpid:  216447
NSpgid: 216447
NSsid:  3994523
Kthread:        0
VmPeak:    10392 kB
VmSize:    10356 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:      6400 kB
VmRSS:      6400 kB
RssAnon:            1536 kB
RssFile:            4864 kB
RssShmem:              0 kB
VmData:     1384 kB
VmStk:       136 kB
VmExe:      2860 kB
VmLib:      2372 kB
VmPTE:        64 kB
VmSwap:        0 kB
HugetlbPages:          0 kB
CoreDumping:    0
THP_enabled:    1
untag_mask:     0xffffffffffffffff
Threads:        1
SigQ:   0/253444
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: 0000000000001000
SigCgt: 0000000000000440
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Seccomp_filters:        0
Speculation_Store_Bypass:       thread vulnerable
SpeculationIndirectBranch:      conditional enabled
Cpus_allowed:   ffffffff
Cpus_allowed_list:      0-31
Mems_allowed:   00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        1
nonvoluntary_ctxt_switches:     0
x86_Thread_features:
x86_Thread_features_locked:
`

	_, err = file.WriteString(content)
	if err != nil {
		return "", err
	}

	return filePath, nil
}

func Benchmark_newProcStatus(b *testing.B) {
	filePath, err := createMockStatusFile()
	if err != nil {
		os.Remove(filePath)
		b.Fatalf("Failed to create mock status file: %v", err)
	}
	defer os.Remove(filePath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = newProcStatus(filePath)
	}
}
