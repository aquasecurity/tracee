package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Tracee drops events of its own process, and the integration tests load it
// into the test binary. The FD path workloads therefore run in a subprocess:
// this binary, re-executed with fdPathHelperEnv naming the workload.
const (
	fdPathHelperEnv     = "TRACEE_FD_PATHS_HELPER"
	fdPathHelperRootEnv = "TRACEE_FD_PATHS_ROOT"
	// Workload threads rename themselves, so a comm scope selects their
	// syscalls and leaves the Go runtime's other threads out.
	fdPathHelperComm = "fdp-helper"
	// Reports are tagged: the test binary also prints its own result.
	fdPathReportPrefix = "FDP "
	// Descriptors the workloads close are moved here, away from the runtime's.
	fdPathFirstFD = 10000
)

// fdPathCase is one descriptor used by a workload. Path is what Tracee must
// report for it, or empty when the descriptor must stay numeric.
type fdPathCase struct {
	Name string `json:"name"`
	FD   int    `json:"fd"`
	Path string `json:"path"`
}

type fdPathReport struct {
	PID   int          `json:"pid"`
	TID   int          `json:"tid"`
	Cases []fdPathCase `json:"cases"`
}

var fdPathWorkloads = map[string]func(root string) error{
	"paths":      fdPathWorkloadPaths,
	"arguments":  fdPathWorkloadArguments,
	"blocked":    func(root string) error { return fdPathWorkloadBlocked(root, 1) },
	"capacity":   func(root string) error { return fdPathWorkloadBlocked(root, 4) },
	"exec":       fdPathWorkloadExec,
	"concurrent": fdPathWorkloadConcurrent,
}

func Test_FdPathsHelper(t *testing.T) {
	name := os.Getenv(fdPathHelperEnv)
	if name == "" {
		t.Skip("subprocess helper of the FD path tests")
	}
	workload, ok := fdPathWorkloads[name]
	if !ok {
		t.Fatalf("unknown workload %q", name)
	}
	if err := workload(os.Getenv(fdPathHelperRootEnv)); err != nil {
		t.Fatal(err)
	}
}

func fdPathSendReport(cases []fdPathCase) error {
	line, err := json.Marshal(fdPathReport{PID: os.Getpid(), TID: unix.Gettid(), Cases: cases})
	if err != nil {
		return err
	}
	_, err = fmt.Printf("%s%s\n", fdPathReportPrefix, line)
	return err
}

// fdPathEnterScope locks the goroutine to its thread and brings that thread
// into the policy scope. The thread is never unlocked: it ends with the
// goroutine, so the runtime cannot reuse a thread that carries this name.
func fdPathEnterScope() error {
	runtime.LockOSThread()
	name, err := unix.BytePtrFromString(fdPathHelperComm)
	if err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(name)), 0, 0, 0)
}

// fdPathCreate creates a file whose absolute path has exactly length bytes.
// Relative operations build it, so length may exceed what one syscall accepts.
func fdPathCreate(root string, length int) (int, string, error) {
	dir, err := os.MkdirTemp(root, "p")
	if err != nil {
		return -1, "", err
	}
	dirfd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return -1, "", err
	}
	defer func() { _ = unix.Close(dirfd) }()
	path := dir
	for length-len(path)-1 > unix.NAME_MAX {
		name := strings.Repeat("d", unix.NAME_MAX)
		if err := unix.Mkdirat(dirfd, name, 0o700); err != nil {
			return -1, "", err
		}
		next, err := unix.Openat(dirfd, name, unix.O_DIRECTORY|unix.O_RDONLY, 0)
		if err != nil {
			return -1, "", err
		}
		_ = unix.Close(dirfd)
		dirfd = next
		path += "/" + name
	}
	if length-len(path)-1 < 1 {
		return -1, "", fmt.Errorf("path of %d bytes does not fit below %s", length, dir)
	}
	name := strings.Repeat("f", length-len(path)-1)
	fd, err := unix.Openat(dirfd, name, unix.O_CREAT|unix.O_RDWR, 0o600)
	if err != nil {
		return -1, "", err
	}
	return fd, path + "/" + name, nil
}

// fdPathMove moves a descriptor to a number the runtime does not use.
func fdPathMove(fd, target int) (int, error) {
	moved, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, target)
	if err != nil {
		return -1, err
	}
	return moved, unix.Close(fd)
}

// fdPathWorkloadPaths closes descriptors at the capture bounds: the longest
// path that fits, the first that does not, a path with more components than
// the traversal follows, a name that is not valid UTF-8, and invalid FDs.
func fdPathWorkloadPaths(root string) error {
	if err := fdPathEnterScope(); err != nil {
		return err
	}
	var cases []fdPathCase
	add := func(name string, fd int, path string) error {
		moved, err := fdPathMove(fd, fdPathFirstFD+len(cases))
		if err != nil {
			return err
		}
		cases = append(cases, fdPathCase{Name: name, FD: moved, Path: path})
		return nil
	}
	for _, length := range []int{63, 64, 255, 256, 1000} {
		fd, path, err := fdPathCreate(root, length)
		if err != nil {
			return err
		}
		if length > 255 {
			path = "" // MAX_FD_PATH_SIZE includes the NUL
		}
		if err := add(fmt.Sprintf("length %d", length), fd, path); err != nil {
			return err
		}
	}

	deep := filepath.Join(root, strings.Repeat("d/", 25))
	if err := os.MkdirAll(deep, 0o700); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(deep, "file"), unix.O_CREAT|unix.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := add("deep", fd, ""); err != nil {
		return err
	}

	fd, err = unix.Open(filepath.Join(root, "a\xffb"), unix.O_CREAT|unix.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := add("invalid UTF-8", fd, filepath.Join(root, "ab")); err != nil {
		return err
	}

	for _, c := range cases {
		if err := unix.Close(c.FD); err != nil {
			return err
		}
	}
	closed := cases[0].FD
	for _, invalid := range []int{-1, 1 << 30, closed} {
		if err := unix.Close(invalid); err != unix.EBADF {
			return fmt.Errorf("close(%d) returned %v", invalid, err)
		}
		cases = append(cases, fdPathCase{Name: fmt.Sprintf("invalid %d", invalid), FD: invalid})
	}
	return fdPathSendReport(cases)
}

// fdPathWorkloadArguments uses syscalls whose descriptor is not the first
// argument, is not named fd, or is not an int32 in the event definition.
func fdPathWorkloadArguments(root string) error {
	if err := fdPathEnterScope(); err != nil {
		return err
	}
	filePath := filepath.Join(root, "file")
	file, err := unix.Open(filePath, unix.O_CREAT|unix.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := unix.Ftruncate(file, 4096); err != nil {
		return err
	}
	dir, err := unix.Open(root, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}

	duplicate, err := unix.Dup(file)
	if err != nil {
		return err
	}
	_ = unix.Close(duplicate)
	if _, err := unix.Getdents(dir, make([]byte, 4096)); err != nil {
		return err
	}
	opened, err := unix.Openat(dir, "file", unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	_ = unix.Close(opened)
	if err := unix.Symlinkat("file", dir, "link"); err != nil {
		return err
	}
	mapped, err := unix.Mmap(file, 0, 4096, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return err
	}
	_ = unix.Munmap(mapped)
	// fsconfig rejects an ordinary file, but its entry still has a valid FD.
	if _, _, errno := unix.Syscall6(unix.SYS_FSCONFIG, uintptr(file), unix.FSCONFIG_CMD_CREATE, 0, 0, 0, 0); errno == 0 {
		return errors.New("fsconfig accepted an ordinary file")
	}
	if _, err := unix.Getsockname(socket); err != nil {
		return err
	}
	missing, err := unix.BytePtrFromString("missing-executable")
	if err != nil {
		return err
	}
	if _, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(dir), uintptr(unsafe.Pointer(missing)), 0, 0, 0, 0); errno != unix.ENOENT {
		return fmt.Errorf("execveat returned %v", errno)
	}

	return fdPathSendReport([]fdPathCase{
		{Name: "dup:oldfd", FD: file, Path: filePath},
		{Name: "getdents64:fd", FD: dir, Path: root},
		{Name: "openat:dirfd", FD: dir, Path: root},
		{Name: "symlinkat:newdirfd", FD: dir, Path: root},
		{Name: "mmap:fd", FD: file, Path: filePath},
		{Name: "fsconfig:fs_fd", FD: file, Path: filePath},
		{Name: "execveat:dirfd", FD: dir, Path: root},
		{Name: "getsockname:sockfd", FD: socket},
	})
}

// fdPathWorkloadBlocked parks threads in read(2), one FIFO each, until the
// test writes to the FIFOs. A snapshot exists for as long as a read is parked.
func fdPathWorkloadBlocked(root string, threads int) error {
	done := make(chan error, threads)
	for i := 0; i < threads; i++ {
		go func() {
			if err := fdPathEnterScope(); err != nil {
				done <- err
				return
			}
			path := filepath.Join(root, fmt.Sprintf("fifo-%d", i))
			if err := unix.Mkfifo(path, 0o600); err != nil {
				done <- err
				return
			}
			fd, err := unix.Open(path, unix.O_RDWR, 0)
			if err != nil {
				done <- err
				return
			}
			if fd, err = fdPathMove(fd, fdPathFirstFD+i); err != nil {
				done <- err
				return
			}
			if err := fdPathSendReport([]fdPathCase{{Name: "read", FD: fd, Path: path}}); err != nil {
				done <- err
				return
			}
			_, err = unix.Read(fd, make([]byte, 1))
			done <- err
		}()
	}
	for i := 0; i < threads; i++ {
		if err := <-done; err != nil {
			return err
		}
	}
	return nil
}

// fdPathWorkloadExec replaces the process from a thread that is not the group
// leader. de_thread() gives that thread the leader's TID, so no syscall exit
// runs under the TID that captured the path.
func fdPathWorkloadExec(string) error {
	runtime.LockOSThread() // keep the leader away from the goroutine below
	failed := make(chan error, 1)
	go func() {
		if err := fdPathEnterScope(); err != nil {
			failed <- err
			return
		}
		if unix.Gettid() == os.Getpid() {
			failed <- errors.New("workload runs on the group leader")
			return
		}
		fd, err := unix.Open("/usr/bin/true", unix.O_RDONLY, 0)
		if err != nil {
			failed <- err
			return
		}
		if err := fdPathSendReport([]fdPathCase{{Name: "execveat:dirfd", FD: fd, Path: "/usr/bin/true"}}); err != nil {
			failed <- err
			return
		}
		empty := []byte{0}
		arg0, _ := unix.BytePtrFromString("true")
		argv := []*byte{arg0, nil}
		envp := []*byte{nil}
		_, _, errno := unix.RawSyscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(&empty[0])),
			uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envp[0])), unix.AT_EMPTY_PATH, 0)
		failed <- fmt.Errorf("execveat returned %v", errno)
	}()
	return <-failed
}

// fdPathWorkloadConcurrent reuses descriptor numbers from several threads at
// once. Every thread owns one path, so a snapshot of another thread shows up
// as a wrong path.
func fdPathWorkloadConcurrent(root string) error {
	const threads, calls = 8, 160
	done := make(chan error, threads)
	for i := 0; i < threads; i++ {
		go func() {
			// Set up before entering the scope: only the calls below are counted.
			fd, path, err := fdPathCreate(root, 128+i*16)
			if err != nil {
				done <- err
				return
			}
			if err := fdPathEnterScope(); err != nil {
				done <- err
				return
			}
			for n := 0; n < calls; n++ {
				duplicate, err := unix.Dup(fd)
				if err != nil {
					done <- err
					return
				}
				if err := unix.Close(duplicate); err != nil {
					done <- err
					return
				}
			}
			done <- fdPathSendReport([]fdPathCase{{Name: "dup", FD: fd, Path: path}})
		}()
	}
	for i := 0; i < threads; i++ {
		if err := <-done; err != nil {
			return err
		}
	}
	return nil
}
