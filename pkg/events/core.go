package events

import (
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/types/trace"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

var CoreEventDefinitionGroup = EventDefinitionGroup{
	events: map[ID]*EventDefinition{
		Read: {
			id32Bit: sys32read,
			name:    "read",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
			},
		},
		Write: {
			id32Bit: sys32write,
			name:    "write",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
			},
		},
		Open: {
			id32Bit: sys32open,
			name:    "open",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Close: {
			id32Bit: sys32close,
			name:    "close",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Stat: {
			id32Bit: sys32stat,
			name:    "stat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat*", Name: "statbuf"},
			},
		},
		Fstat: {
			id32Bit: sys32fstat,
			name:    "fstat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct stat*", Name: "statbuf"},
			},
		},
		Lstat: {
			id32Bit: sys32lstat,
			name:    "lstat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat*", Name: "statbuf"},
			},
		},
		Poll: {
			id32Bit: sys32poll,
			name:    "poll",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "struct pollfd*", Name: "fds"},
				{Type: "unsigned int", Name: "nfds"},
				{Type: "int", Name: "timeout"},
			},
		},
		Lseek: {
			id32Bit: sys32lseek,
			name:    "lseek",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "offset"},
				{Type: "unsigned int", Name: "whence"},
			},
		},
		Mmap: {
			id32Bit: sys32mmap,
			name:    "mmap",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "int", Name: "prot"},
				{Type: "int", Name: "flags"},
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "off"},
			},
		},
		Mprotect: {
			id32Bit: sys32mprotect,
			name:    "mprotect",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "prot"},
			},
		},
		Munmap: {
			id32Bit: sys32munmap,
			name:    "munmap",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
			},
		},
		Brk: {
			id32Bit: sys32brk,
			name:    "brk",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
			},
		},
		RtSigaction: {
			id32Bit: sys32rt_sigaction,
			name:    "rt_sigaction",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "signum"},
				{Type: "const struct sigaction*", Name: "act"},
				{Type: "struct sigaction*", Name: "oldact"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		RtSigprocmask: {
			id32Bit: sys32rt_sigprocmask,
			name:    "rt_sigprocmask",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "how"},
				{Type: "sigset_t*", Name: "set"},
				{Type: "sigset_t*", Name: "oldset"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		RtSigreturn: {
			id32Bit: sys32rt_sigreturn,
			name:    "rt_sigreturn",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params:  []trace.ArgMeta{},
		},
		Ioctl: {
			id32Bit: sys32ioctl,
			name:    "ioctl",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "unsigned long", Name: "request"},
				{Type: "unsigned long", Name: "arg"},
			},
		},
		Pread64: {
			id32Bit: sys32pread64,
			name:    "pread64",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "offset"},
			},
		},
		Pwrite64: {
			id32Bit: sys32pwrite64,
			name:    "pwrite64",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "offset"},
			},
		},
		Readv: {
			id32Bit: sys32readv,
			name:    "readv",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "int", Name: "iovcnt"},
			},
		},
		Writev: {
			id32Bit: sys32writev,
			name:    "writev",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "int", Name: "iovcnt"},
			},
		},
		Access: {
			id32Bit: sys32access,
			name:    "access",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "mode"},
			},
		},
		Pipe: {
			id32Bit: sys32pipe,
			name:    "pipe",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			params: []trace.ArgMeta{
				{Type: "int[2]", Name: "pipefd"},
			},
		},
		Select: {
			id32Bit: sys32_newselect,
			name:    "select",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "nfds"},
				{Type: "fd_set*", Name: "readfds"},
				{Type: "fd_set*", Name: "writefds"},
				{Type: "fd_set*", Name: "exceptfds"},
				{Type: "struct timeval*", Name: "timeout"},
			},
		},
		SchedYield: {
			id32Bit: sys32sched_yield,
			name:    "sched_yield",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params:  []trace.ArgMeta{},
		},
		Mremap: {
			id32Bit: sys32mremap,
			name:    "mremap",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "old_address"},
				{Type: "size_t", Name: "old_size"},
				{Type: "size_t", Name: "new_size"},
				{Type: "int", Name: "flags"},
				{Type: "void*", Name: "new_address"},
			},
		},
		Msync: {
			id32Bit: sys32msync,
			name:    "msync",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_sync"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "int", Name: "flags"},
			},
		},
		Mincore: {
			id32Bit: sys32mincore,
			name:    "mincore",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "unsigned char*", Name: "vec"},
			},
		},
		Madvise: {
			id32Bit: sys32madvise,
			name:    "madvise",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "int", Name: "advice"},
			},
		},
		Shmget: {
			id32Bit: sys32shmget,
			name:    "shmget",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_shm"},
			params: []trace.ArgMeta{
				{Type: "key_t", Name: "key"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "shmflg"},
			},
		},
		Shmat: {
			id32Bit: sys32shmat,
			name:    "shmat",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_shm"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "shmid"},
				{Type: "const void*", Name: "shmaddr"},
				{Type: "int", Name: "shmflg"},
			},
		},
		Shmctl: {
			id32Bit: sys32shmctl,
			name:    "shmctl",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_shm"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "shmid"},
				{Type: "int", Name: "cmd"},
				{Type: "struct shmid_ds*", Name: "buf"},
			},
		},
		Dup: {
			id32Bit: sys32dup,
			name:    "dup",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "oldfd"},
			},
		},
		Dup2: {
			id32Bit: sys32dup2,
			name:    "dup2",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "oldfd"},
				{Type: "int", Name: "newfd"},
			},
		},
		Pause: {
			id32Bit: sys32pause,
			name:    "pause",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params:  []trace.ArgMeta{},
		},
		Nanosleep: {
			id32Bit: sys32nanosleep,
			name:    "nanosleep",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "const struct timespec*", Name: "req"},
				{Type: "struct timespec*", Name: "rem"},
			},
		},
		Getitimer: {
			id32Bit: sys32getitimer,
			name:    "getitimer",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "struct itimerval*", Name: "curr_value"},
			},
		},
		Alarm: {
			id32Bit: sys32alarm,
			name:    "alarm",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "seconds"},
			},
		},
		Setitimer: {
			id32Bit: sys32setitimer,
			name:    "setitimer",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "struct itimerval*", Name: "new_value"},
				{Type: "struct itimerval*", Name: "old_value"},
			},
		},
		Getpid: {
			id32Bit: sys32getpid,
			name:    "getpid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Sendfile: {
			id32Bit: sys32sendfile64,
			name:    "sendfile",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "out_fd"},
				{Type: "int", Name: "in_fd"},
				{Type: "off_t*", Name: "offset"},
				{Type: "size_t", Name: "count"},
			},
		},
		Socket: {
			id32Bit: sys32socket,
			name:    "socket",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "domain"},
				{Type: "int", Name: "type"},
				{Type: "int", Name: "protocol"},
			},
		},
		Connect: {
			id32Bit: sys32connect,
			name:    "connect",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int", Name: "addrlen"},
			},
		},
		Accept: {
			id32Bit: sys32undefined,
			name:    "accept",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int*", Name: "addrlen"},
			},
		},
		Sendto: {
			id32Bit: sys32sendto,
			name:    "sendto",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_snd_rcv"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "flags"},
				{Type: "struct sockaddr*", Name: "dest_addr"},
				{Type: "int", Name: "addrlen"},
			},
		},
		Recvfrom: {
			id32Bit: sys32recvfrom,
			name:    "recvfrom",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_snd_rcv"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "flags"},
				{Type: "struct sockaddr*", Name: "src_addr"},
				{Type: "int*", Name: "addrlen"},
			},
		},
		Sendmsg: {
			id32Bit: sys32sendmsg,
			name:    "sendmsg",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_snd_rcv"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct msghdr*", Name: "msg"},
				{Type: "int", Name: "flags"},
			},
		},
		Recvmsg: {
			id32Bit: sys32recvmsg,
			name:    "recvmsg",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_snd_rcv"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct msghdr*", Name: "msg"},
				{Type: "int", Name: "flags"},
			},
		},
		Shutdown: {
			id32Bit: sys32shutdown,
			name:    "shutdown",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "how"},
			},
		},
		Bind: {
			id32Bit: sys32bind,
			name:    "bind",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int", Name: "addrlen"},
			},
		},
		Listen: {
			id32Bit: sys32listen,
			name:    "listen",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "backlog"},
			},
		},
		Getsockname: {
			id32Bit: sys32getsockname,
			name:    "getsockname",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int*", Name: "addrlen"},
			},
		},
		Getpeername: {
			id32Bit: sys32getpeername,
			name:    "getpeername",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int*", Name: "addrlen"},
			},
		},
		Socketpair: {
			id32Bit: sys32socketpair,
			name:    "socketpair",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "domain"},
				{Type: "int", Name: "type"},
				{Type: "int", Name: "protocol"},
				{Type: "int[2]", Name: "sv"},
			},
		},
		Setsockopt: {
			id32Bit: sys32setsockopt,
			name:    "setsockopt",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "level"},
				{Type: "int", Name: "optname"},
				{Type: "const void*", Name: "optval"},
				{Type: "int", Name: "optlen"},
			},
		},
		Getsockopt: {
			id32Bit: sys32getsockopt,
			name:    "getsockopt",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "level"},
				{Type: "int", Name: "optname"},
				{Type: "void*", Name: "optval"},
				{Type: "int*", Name: "optlen"},
			},
		},
		Clone: {
			id32Bit: sys32clone,
			name:    "clone",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "flags"},
				{Type: "void*", Name: "stack"},
				{Type: "int*", Name: "parent_tid"},
				{Type: "int*", Name: "child_tid"},
				{Type: "unsigned long", Name: "tls"},
			},
		},
		Fork: {
			id32Bit: sys32fork,
			name:    "fork",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_life"},
			params:  []trace.ArgMeta{},
		},
		Vfork: {
			id32Bit: sys32vfork,
			name:    "vfork",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_life"},
			params:  []trace.ArgMeta{},
		},
		Execve: {
			id32Bit: sys32execve,
			name:    "execve",
			syscall: true,
			dependencies: Dependencies{
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_tails",
						"syscall__execve",
						[]uint32{uint32(Execve)},
					),
				},
			},
			sets: []string{"syscalls", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "const char*const*", Name: "argv"},
				{Type: "const char*const*", Name: "envp"},
			},
		},
		Exit: {
			id32Bit: sys32exit,
			name:    "exit",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "status"},
			},
		},
		Wait4: {
			id32Bit: sys32wait4,
			name:    "wait4",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int*", Name: "wstatus"},
				{Type: "int", Name: "options"},
				{Type: "struct rusage*", Name: "rusage"},
			},
		},
		Kill: {
			id32Bit: sys32kill,
			name:    "kill",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int", Name: "sig"},
			},
		},
		Uname: {
			id32Bit: sys32uname,
			name:    "uname",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "struct utsname*", Name: "buf"},
			},
		},
		Semget: {
			id32Bit: sys32semget,
			name:    "semget",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_sem"},
			params: []trace.ArgMeta{
				{Type: "key_t", Name: "key"},
				{Type: "int", Name: "nsems"},
				{Type: "int", Name: "semflg"},
			},
		},
		Semop: {
			id32Bit: sys32undefined,
			name:    "semop",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_sem"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "semid"},
				{Type: "struct sembuf*", Name: "sops"},
				{Type: "size_t", Name: "nsops"},
			},
		},
		Semctl: {
			id32Bit: sys32semctl,
			name:    "semctl",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_sem"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "semid"},
				{Type: "int", Name: "semnum"},
				{Type: "int", Name: "cmd"},
				{Type: "unsigned long", Name: "arg"},
			},
		},
		Shmdt: {
			id32Bit: sys32shmdt,
			name:    "shmdt",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_shm"},
			params: []trace.ArgMeta{
				{Type: "const void*", Name: "shmaddr"},
			},
		},
		Msgget: {
			id32Bit: sys32msgget,
			name:    "msgget",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "key_t", Name: "key"},
				{Type: "int", Name: "msgflg"},
			},
		},
		Msgsnd: {
			id32Bit: sys32msgsnd,
			name:    "msgsnd",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "msqid"},
				{Type: "struct msgbuf*", Name: "msgp"},
				{Type: "size_t", Name: "msgsz"},
				{Type: "int", Name: "msgflg"},
			},
		},
		Msgrcv: {
			id32Bit: sys32msgrcv,
			name:    "msgrcv",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "msqid"},
				{Type: "struct msgbuf*", Name: "msgp"},
				{Type: "size_t", Name: "msgsz"},
				{Type: "long", Name: "msgtyp"},
				{Type: "int", Name: "msgflg"},
			},
		},
		Msgctl: {
			id32Bit: sys32msgctl,
			name:    "msgctl",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "msqid"},
				{Type: "int", Name: "cmd"},
				{Type: "struct msqid_ds*", Name: "buf"},
			},
		},
		Fcntl: {
			id32Bit: sys32fcntl,
			name:    "fcntl",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "cmd"},
				{Type: "unsigned long", Name: "arg"},
			},
		},
		Flock: {
			id32Bit: sys32flock,
			name:    "flock",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "operation"},
			},
		},
		Fsync: {
			id32Bit: sys32fsync,
			name:    "fsync",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_sync"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Fdatasync: {
			id32Bit: sys32fdatasync,
			name:    "fdatasync",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_sync"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Truncate: {
			id32Bit: sys32truncate,
			name:    "truncate",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "off_t", Name: "length"},
			},
		},
		Ftruncate: {
			id32Bit: sys32ftruncate,
			name:    "ftruncate",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "length"},
			},
		},
		Getdents: {
			id32Bit: sys32getdents,
			name:    "getdents",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct linux_dirent*", Name: "dirp"},
				{Type: "unsigned int", Name: "count"},
			},
		},
		Getcwd: {
			id32Bit: sys32getcwd,
			name:    "getcwd",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "char*", Name: "buf"},
				{Type: "size_t", Name: "size"},
			},
		},
		Chdir: {
			id32Bit: sys32chdir,
			name:    "chdir",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
			},
		},
		Fchdir: {
			id32Bit: sys32fchdir,
			name:    "fchdir",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Rename: {
			id32Bit: sys32rename,
			name:    "rename",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "oldpath"},
				{Type: "const char*", Name: "newpath"},
			},
		},
		Mkdir: {
			id32Bit: sys32mkdir,
			name:    "mkdir",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Rmdir: {
			id32Bit: sys32rmdir,
			name:    "rmdir",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
			},
		},
		Creat: {
			id32Bit: sys32creat,
			name:    "creat",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Link: {
			id32Bit: sys32link,
			name:    "link",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_link_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "oldpath"},
				{Type: "const char*", Name: "newpath"},
			},
		},
		Unlink: {
			id32Bit: sys32unlink,
			name:    "unlink",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_link_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
			},
		},
		Symlink: {
			id32Bit: sys32symlink,
			name:    "symlink",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_link_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "target"},
				{Type: "const char*", Name: "linkpath"},
			},
		},
		Readlink: {
			id32Bit: sys32readlink,
			name:    "readlink",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_link_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "char*", Name: "buf"},
				{Type: "size_t", Name: "bufsiz"},
			},
		},
		Chmod: {
			id32Bit: sys32chmod,
			name:    "chmod",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Fchmod: {
			id32Bit: sys32fchmod,
			name:    "fchmod",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Chown: {
			id32Bit: sys32chown32,
			name:    "chown",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "uid_t", Name: "owner"},
				{Type: "gid_t", Name: "group"},
			},
		},
		Fchown: {
			id32Bit: sys32fchown32,
			name:    "fchown",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "uid_t", Name: "owner"},
				{Type: "gid_t", Name: "group"},
			},
		},
		Lchown: {
			id32Bit: sys32lchown32,
			name:    "lchown",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "uid_t", Name: "owner"},
				{Type: "gid_t", Name: "group"},
			},
		},
		Umask: {
			id32Bit: sys32umask,
			name:    "umask",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "mode_t", Name: "mask"},
			},
		},
		Gettimeofday: {
			id32Bit: sys32gettimeofday,
			name:    "gettimeofday",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_tod"},
			params: []trace.ArgMeta{
				{Type: "struct timeval*", Name: "tv"},
				{Type: "struct timezone*", Name: "tz"},
			},
		},
		Getrlimit: {
			id32Bit: sys32ugetrlimit,
			name:    "getrlimit",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "resource"},
				{Type: "struct rlimit*", Name: "rlim"},
			},
		},
		Getrusage: {
			id32Bit: sys32getrusage,
			name:    "getrusage",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "who"},
				{Type: "struct rusage*", Name: "usage"},
			},
		},
		Sysinfo: {
			id32Bit: sys32sysinfo,
			name:    "sysinfo",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "struct sysinfo*", Name: "info"},
			},
		},
		Times: {
			id32Bit: sys32times,
			name:    "times",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "struct tms*", Name: "buf"},
			},
		},
		Ptrace: {
			id32Bit: sys32ptrace,
			name:    "ptrace",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "long", Name: "request"},
				{Type: "pid_t", Name: "pid"},
				{Type: "void*", Name: "addr"},
				{Type: "void*", Name: "data"},
			},
		},
		Getuid: {
			id32Bit: sys32getuid32,
			name:    "getuid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Syslog: {
			id32Bit: sys32syslog,
			name:    "syslog",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "type"},
				{Type: "char*", Name: "bufp"},
				{Type: "int", Name: "len"},
			},
		},
		Getgid: {
			id32Bit: sys32getgid32,
			name:    "getgid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Setuid: {
			id32Bit: sys32setuid32,
			name:    "setuid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "uid_t", Name: "uid"},
			},
		},
		Setgid: {
			id32Bit: sys32setgid32,
			name:    "setgid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "gid_t", Name: "gid"},
			},
		},
		Geteuid: {
			id32Bit: sys32geteuid32,
			name:    "geteuid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Getegid: {
			id32Bit: sys32getegid32,
			name:    "getegid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Setpgid: {
			id32Bit: sys32setpgid,
			name:    "setpgid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "pid_t", Name: "pgid"},
			},
		},
		Getppid: {
			id32Bit: sys32getppid,
			name:    "getppid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Getpgrp: {
			id32Bit: sys32getpgrp,
			name:    "getpgrp",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Setsid: {
			id32Bit: sys32setsid,
			name:    "setsid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Setreuid: {
			id32Bit: sys32setreuid32,
			name:    "setreuid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "uid_t", Name: "ruid"},
				{Type: "uid_t", Name: "euid"},
			},
		},
		Setregid: {
			id32Bit: sys32setregid32,
			name:    "setregid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "gid_t", Name: "rgid"},
				{Type: "gid_t", Name: "egid"},
			},
		},
		Getgroups: {
			id32Bit: sys32getgroups32,
			name:    "getgroups",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "size"},
				{Type: "gid_t*", Name: "list"},
			},
		},
		Setgroups: {
			id32Bit: sys32setgroups32,
			name:    "setgroups",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "size"},
				{Type: "gid_t*", Name: "list"},
			},
		},
		Setresuid: {
			id32Bit: sys32setresuid32,
			name:    "setresuid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "uid_t", Name: "ruid"},
				{Type: "uid_t", Name: "euid"},
				{Type: "uid_t", Name: "suid"},
			},
		},
		Getresuid: {
			id32Bit: sys32getresuid32,
			name:    "getresuid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "uid_t*", Name: "ruid"},
				{Type: "uid_t*", Name: "euid"},
				{Type: "uid_t*", Name: "suid"},
			},
		},
		Setresgid: {
			id32Bit: sys32setresgid32,
			name:    "setresgid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "gid_t", Name: "rgid"},
				{Type: "gid_t", Name: "egid"},
				{Type: "gid_t", Name: "sgid"},
			},
		},
		Getresgid: {
			id32Bit: sys32getresgid32,
			name:    "getresgid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "gid_t*", Name: "rgid"},
				{Type: "gid_t*", Name: "egid"},
				{Type: "gid_t*", Name: "sgid"},
			},
		},
		Getpgid: {
			id32Bit: sys32getpgid,
			name:    "getpgid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
			},
		},
		Setfsuid: {
			id32Bit: sys32setfsuid32,
			name:    "setfsuid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "uid_t", Name: "fsuid"},
			},
		},
		Setfsgid: {
			id32Bit: sys32setfsgid32,
			name:    "setfsgid",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "gid_t", Name: "fsgid"},
			},
		},
		Getsid: {
			id32Bit: sys32getsid,
			name:    "getsid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
			},
		},
		Capget: {
			id32Bit: sys32capget,
			name:    "capget",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "cap_user_header_t", Name: "hdrp"},
				{Type: "cap_user_data_t", Name: "datap"},
			},
		},
		Capset: {
			id32Bit: sys32capset,
			name:    "capset",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "cap_user_header_t", Name: "hdrp"},
				{Type: "const cap_user_data_t", Name: "datap"},
			},
		},
		RtSigpending: {
			id32Bit: sys32rt_sigpending,
			name:    "rt_sigpending",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "sigset_t*", Name: "set"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		RtSigtimedwait: {
			id32Bit: sys32rt_sigtimedwait_time64,
			name:    "rt_sigtimedwait",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "const sigset_t*", Name: "set"},
				{Type: "siginfo_t*", Name: "info"},
				{Type: "const struct timespec*", Name: "timeout"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		RtSigqueueinfo: {
			id32Bit: sys32rt_sigqueueinfo,
			name:    "rt_sigqueueinfo",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "tgid"},
				{Type: "int", Name: "sig"},
				{Type: "siginfo_t*", Name: "info"},
			},
		},
		RtSigsuspend: {
			id32Bit: sys32rt_sigsuspend,
			name:    "rt_sigsuspend",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "sigset_t*", Name: "mask"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		Sigaltstack: {
			id32Bit: sys32sigaltstack,
			name:    "sigaltstack",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "const stack_t*", Name: "ss"},
				{Type: "stack_t*", Name: "old_ss"},
			},
		},
		Utime: {
			id32Bit: sys32utime,
			name:    "utime",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "filename"},
				{Type: "const struct utimbuf*", Name: "times"},
			},
		},
		Mknod: {
			id32Bit: sys32mknod,
			name:    "mknod",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
				{Type: "dev_t", Name: "dev"},
			},
		},
		Uselib: {
			id32Bit: sys32uselib,
			name:    "uselib",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "library"},
			},
		},
		Personality: {
			id32Bit: sys32personality,
			name:    "personality",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "persona"},
			},
		},
		Ustat: {
			id32Bit: sys32ustat,
			name:    "ustat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_info"},
			params: []trace.ArgMeta{
				{Type: "dev_t", Name: "dev"},
				{Type: "struct ustat*", Name: "ubuf"},
			},
		},
		Statfs: {
			id32Bit: sys32statfs,
			name:    "statfs",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_info"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "struct statfs*", Name: "buf"},
			},
		},
		Fstatfs: {
			id32Bit: sys32fstatfs,
			name:    "fstatfs",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_info"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct statfs*", Name: "buf"},
			},
		},
		Sysfs: {
			id32Bit: sys32sysfs,
			name:    "sysfs",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_info"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "option"},
			},
		},
		Getpriority: {
			id32Bit: sys32getpriority,
			name:    "getpriority",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
			},
		},
		Setpriority: {
			id32Bit: sys32setpriority,
			name:    "setpriority",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
				{Type: "int", Name: "prio"},
			},
		},
		SchedSetparam: {
			id32Bit: sys32sched_setparam,
			name:    "sched_setparam",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct sched_param*", Name: "param"},
			},
		},
		SchedGetparam: {
			id32Bit: sys32sched_getparam,
			name:    "sched_getparam",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct sched_param*", Name: "param"},
			},
		},
		SchedSetscheduler: {
			id32Bit: sys32sched_setscheduler,
			name:    "sched_setscheduler",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int", Name: "policy"},
				{Type: "struct sched_param*", Name: "param"},
			},
		},
		SchedGetscheduler: {
			id32Bit: sys32sched_getscheduler,
			name:    "sched_getscheduler",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
			},
		},
		SchedGetPriorityMax: {
			id32Bit: sys32sched_get_priority_max,
			name:    "sched_get_priority_max",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "policy"},
			},
		},
		SchedGetPriorityMin: {
			id32Bit: sys32sched_get_priority_min,
			name:    "sched_get_priority_min",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "policy"},
			},
		},
		SchedRrGetInterval: {
			id32Bit: sys32sched_rr_get_interval_time64,
			name:    "sched_rr_get_interval",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct timespec*", Name: "tp"},
			},
		},
		Mlock: {
			id32Bit: sys32mlock,
			name:    "mlock",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "const void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
			},
		},
		Munlock: {
			id32Bit: sys32munlock,
			name:    "munlock",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "const void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
			},
		},
		Mlockall: {
			id32Bit: sys32mlockall,
			name:    "mlockall",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		Munlockall: {
			id32Bit: sys32munlockall,
			name:    "munlockall",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params:  []trace.ArgMeta{},
		},
		Vhangup: {
			id32Bit: sys32vhangup,
			name:    "vhangup",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params:  []trace.ArgMeta{},
		},
		ModifyLdt: {
			id32Bit: sys32modify_ldt,
			name:    "modify_ldt",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "func"},
				{Type: "void*", Name: "ptr"},
				{Type: "unsigned long", Name: "bytecount"},
			},
		},
		PivotRoot: {
			id32Bit: sys32pivot_root,
			name:    "pivot_root",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "new_root"},
				{Type: "const char*", Name: "put_old"},
			},
		},
		Sysctl: {
			id32Bit: sys32_sysctl,
			name:    "sysctl",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "struct __sysctl_args*", Name: "args"},
			},
		},
		Prctl: {
			id32Bit: sys32prctl,
			name:    "prctl",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "option"},
				{Type: "unsigned long", Name: "arg2"},
				{Type: "unsigned long", Name: "arg3"},
				{Type: "unsigned long", Name: "arg4"},
				{Type: "unsigned long", Name: "arg5"},
			},
		},
		ArchPrctl: {
			id32Bit: sys32arch_prctl,
			name:    "arch_prctl",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "option"},
				{Type: "unsigned long", Name: "addr"},
			},
		},
		Adjtimex: {
			id32Bit: sys32adjtimex,
			name:    "adjtimex",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_clock"},
			params: []trace.ArgMeta{
				{Type: "struct timex*", Name: "buf"},
			},
		},
		Setrlimit: {
			id32Bit: sys32setrlimit,
			name:    "setrlimit",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "resource"},
				{Type: "const struct rlimit*", Name: "rlim"},
			},
		},
		Chroot: {
			id32Bit: sys32chroot,
			name:    "chroot",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
			},
		},
		Sync: {
			id32Bit: sys32sync,
			name:    "sync",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_sync"},
			params:  []trace.ArgMeta{},
		},
		Acct: {
			id32Bit: sys32acct,
			name:    "acct",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "filename"},
			},
		},
		Settimeofday: {
			id32Bit: sys32settimeofday,
			name:    "settimeofday",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_tod"},
			params: []trace.ArgMeta{
				{Type: "const struct timeval*", Name: "tv"},
				{Type: "const struct timezone*", Name: "tz"},
			},
		},
		Mount: {
			id32Bit: sys32mount,
			name:    "mount",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "source"},
				{Type: "const char*", Name: "target"},
				{Type: "const char*", Name: "filesystemtype"},
				{Type: "unsigned long", Name: "mountflags"},
				{Type: "const void*", Name: "data"},
			},
		},
		Umount2: {
			id32Bit: sys32umount2,
			name:    "umount2",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "target"},
				{Type: "int", Name: "flags"},
			},
		},
		Swapon: {
			id32Bit: sys32swapon,
			name:    "swapon",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "int", Name: "swapflags"},
			},
		},
		Swapoff: {
			id32Bit: sys32swapoff,
			name:    "swapoff",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
			},
		},
		Reboot: {
			id32Bit: sys32reboot,
			name:    "reboot",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "magic"},
				{Type: "int", Name: "magic2"},
				{Type: "int", Name: "cmd"},
				{Type: "void*", Name: "arg"},
			},
		},
		Sethostname: {
			id32Bit: sys32sethostname,
			name:    "sethostname",
			syscall: true,
			sets:    []string{"syscalls", "net"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "size_t", Name: "len"},
			},
		},
		Setdomainname: {
			id32Bit: sys32setdomainname,
			name:    "setdomainname",
			syscall: true,
			sets:    []string{"syscalls", "net"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "size_t", Name: "len"},
			},
		},
		Iopl: {
			id32Bit: sys32iopl,
			name:    "iopl",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "level"},
			},
		},
		Ioperm: {
			id32Bit: sys32ioperm,
			name:    "ioperm",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "from"},
				{Type: "unsigned long", Name: "num"},
				{Type: "int", Name: "turn_on"},
			},
		},
		CreateModule: {
			id32Bit: sys32create_module,
			name:    "create_module",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_module"},
			params:  []trace.ArgMeta{},
		},
		InitModule: {
			id32Bit: sys32init_module,
			name:    "init_module",
			syscall: true,
			sets:    []string{"default", "syscalls", "system", "system_module"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "module_image"},
				{Type: "unsigned long", Name: "len"},
				{Type: "const char*", Name: "param_values"},
			},
		},
		DeleteModule: {
			id32Bit: sys32delete_module,
			name:    "delete_module",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_module"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "int", Name: "flags"},
			},
		},
		GetKernelSyms: {
			id32Bit: sys32get_kernel_syms,
			name:    "get_kernel_syms",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_module"},
			params:  []trace.ArgMeta{},
		},
		QueryModule: {
			id32Bit: sys32query_module,
			name:    "query_module",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_module"},
			params:  []trace.ArgMeta{},
		},
		Quotactl: {
			id32Bit: sys32quotactl,
			name:    "quotactl",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "cmd"},
				{Type: "const char*", Name: "special"},
				{Type: "int", Name: "id"},
				{Type: "void*", Name: "addr"},
			},
		},
		Nfsservctl: {
			id32Bit: sys32nfsservctl,
			name:    "nfsservctl",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params:  []trace.ArgMeta{},
		},
		Getpmsg: {
			id32Bit: sys32getpmsg,
			name:    "getpmsg",
			syscall: true,
			sets:    []string{"syscalls"},
			params:  []trace.ArgMeta{},
		},
		Putpmsg: {
			id32Bit: sys32putpmsg,
			name:    "putpmsg",
			syscall: true,
			sets:    []string{"syscalls"},
			params:  []trace.ArgMeta{},
		},
		Afs: {
			id32Bit: sys32undefined,
			name:    "afs",
			syscall: true,
			sets:    []string{"syscalls"},
			params:  []trace.ArgMeta{},
		},
		Tuxcall: {
			id32Bit: sys32undefined,
			name:    "tuxcall",
			syscall: true,
			sets:    []string{"syscalls"},
			params:  []trace.ArgMeta{},
		},
		Security: {
			id32Bit: sys32undefined,
			name:    "security",
			syscall: true,
			sets:    []string{"syscalls"},
			params:  []trace.ArgMeta{},
		},
		Gettid: {
			id32Bit: sys32gettid,
			name:    "gettid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_ids"},
			params:  []trace.ArgMeta{},
		},
		Readahead: {
			id32Bit: sys32readahead,
			name:    "readahead",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "offset"},
				{Type: "size_t", Name: "count"},
			},
		},
		Setxattr: {
			id32Bit: sys32setxattr,
			name:    "setxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
				{Type: "const void*", Name: "value"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "flags"},
			},
		},
		Lsetxattr: {
			id32Bit: sys32lsetxattr,
			name:    "lsetxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
				{Type: "const void*", Name: "value"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "flags"},
			},
		},
		Fsetxattr: {
			id32Bit: sys32fsetxattr,
			name:    "fsetxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "name"},
				{Type: "const void*", Name: "value"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "flags"},
			},
		},
		Getxattr: {
			id32Bit: sys32getxattr,
			name:    "getxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
				{Type: "void*", Name: "value"},
				{Type: "size_t", Name: "size"},
			},
		},
		Lgetxattr: {
			id32Bit: sys32lgetxattr,
			name:    "lgetxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
				{Type: "void*", Name: "value"},
				{Type: "size_t", Name: "size"},
			},
		},
		Fgetxattr: {
			id32Bit: sys32fgetxattr,
			name:    "fgetxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "name"},
				{Type: "void*", Name: "value"},
				{Type: "size_t", Name: "size"},
			},
		},
		Listxattr: {
			id32Bit: sys32listxattr,
			name:    "listxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "char*", Name: "list"},
				{Type: "size_t", Name: "size"},
			},
		},
		Llistxattr: {
			id32Bit: sys32llistxattr,
			name:    "llistxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "char*", Name: "list"},
				{Type: "size_t", Name: "size"},
			},
		},
		Flistxattr: {
			id32Bit: sys32flistxattr,
			name:    "flistxattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "char*", Name: "list"},
				{Type: "size_t", Name: "size"},
			},
		},
		Removexattr: {
			id32Bit: sys32removexattr,
			name:    "removexattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
			},
		},
		Lremovexattr: {
			id32Bit: sys32lremovexattr,
			name:    "lremovexattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "name"},
			},
		},
		Fremovexattr: {
			id32Bit: sys32fremovexattr,
			name:    "fremovexattr",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "name"},
			},
		},
		Tkill: {
			id32Bit: sys32tkill,
			name:    "tkill",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "tid"},
				{Type: "int", Name: "sig"},
			},
		},
		Time: {
			id32Bit: sys32time,
			name:    "time",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_tod"},
			params: []trace.ArgMeta{
				{Type: "time_t*", Name: "tloc"},
			},
		},
		Futex: {
			id32Bit: sys32futex_time64,
			name:    "futex",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_futex"},
			params: []trace.ArgMeta{
				{Type: "int*", Name: "uaddr"},
				{Type: "int", Name: "futex_op"},
				{Type: "int", Name: "val"},
				{Type: "const struct timespec*", Name: "timeout"},
				{Type: "int*", Name: "uaddr2"},
				{Type: "int", Name: "val3"},
			},
		},
		SchedSetaffinity: {
			id32Bit: sys32sched_setaffinity,
			name:    "sched_setaffinity",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "size_t", Name: "cpusetsize"},
				{Type: "unsigned long*", Name: "mask"},
			},
		},
		SchedGetaffinity: {
			id32Bit: sys32sched_getaffinity,
			name:    "sched_getaffinity",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "size_t", Name: "cpusetsize"},
				{Type: "unsigned long*", Name: "mask"},
			},
		},
		SetThreadArea: {
			id32Bit: sys32set_thread_area,
			name:    "set_thread_area",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "struct user_desc*", Name: "u_info"},
			},
		},
		IoSetup: {
			id32Bit: sys32io_setup,
			name:    "io_setup",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_async_io"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "nr_events"},
				{Type: "io_context_t*", Name: "ctx_idp"},
			},
		},
		IoDestroy: {
			id32Bit: sys32io_destroy,
			name:    "io_destroy",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_async_io"},
			params: []trace.ArgMeta{
				{Type: "io_context_t", Name: "ctx_id"},
			},
		},
		IoGetevents: {
			id32Bit: sys32io_getevents,
			name:    "io_getevents",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_async_io"},
			params: []trace.ArgMeta{
				{Type: "io_context_t", Name: "ctx_id"},
				{Type: "long", Name: "min_nr"},
				{Type: "long", Name: "nr"},
				{Type: "struct io_event*", Name: "events"},
				{Type: "struct timespec*", Name: "timeout"},
			},
		},
		IoSubmit: {
			id32Bit: sys32io_submit,
			name:    "io_submit",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_async_io"},
			params: []trace.ArgMeta{
				{Type: "io_context_t", Name: "ctx_id"},
				{Type: "long", Name: "nr"},
				{Type: "struct iocb**", Name: "iocbpp"},
			},
		},
		IoCancel: {
			id32Bit: sys32io_cancel,
			name:    "io_cancel",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_async_io"},
			params: []trace.ArgMeta{
				{Type: "io_context_t", Name: "ctx_id"},
				{Type: "struct iocb*", Name: "iocb"},
				{Type: "struct io_event*", Name: "result"},
			},
		},
		GetThreadArea: {
			id32Bit: sys32get_thread_area,
			name:    "get_thread_area",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "struct user_desc*", Name: "u_info"},
			},
		},
		LookupDcookie: {
			id32Bit: sys32lookup_dcookie,
			name:    "lookup_dcookie",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "u64", Name: "cookie"},
				{Type: "char*", Name: "buffer"},
				{Type: "size_t", Name: "len"},
			},
		},
		EpollCreate: {
			id32Bit: sys32epoll_create,
			name:    "epoll_create",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "size"},
			},
		},
		EpollCtlOld: {
			id32Bit: sys32undefined,
			name:    "epoll_ctl_old",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params:  []trace.ArgMeta{},
		},
		EpollWaitOld: {
			id32Bit: sys32undefined,
			name:    "epoll_wait_old",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params:  []trace.ArgMeta{},
		},
		RemapFilePages: {
			id32Bit: sys32remap_file_pages,
			name:    "remap_file_pages",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "size"},
				{Type: "int", Name: "prot"},
				{Type: "size_t", Name: "pgoff"},
				{Type: "int", Name: "flags"},
			},
		},
		Getdents64: {
			id32Bit: sys32getdents64,
			name:    "getdents64",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "struct linux_dirent64*", Name: "dirp"},
				{Type: "unsigned int", Name: "count"},
			},
		},
		SetTidAddress: {
			id32Bit: sys32set_tid_address,
			name:    "set_tid_address",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "int*", Name: "tidptr"},
			},
		},
		RestartSyscall: {
			id32Bit: sys32restart_syscall,
			name:    "restart_syscall",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params:  []trace.ArgMeta{},
		},
		Semtimedop: {
			id32Bit: sys32semtimedop_time64,
			name:    "semtimedop",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_sem"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "semid"},
				{Type: "struct sembuf*", Name: "sops"},
				{Type: "size_t", Name: "nsops"},
				{Type: "const struct timespec*", Name: "timeout"},
			},
		},
		Fadvise64: {
			id32Bit: sys32fadvise64,
			name:    "fadvise64",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "offset"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "advice"},
			},
		},
		TimerCreate: {
			id32Bit: sys32timer_create,
			name:    "timer_create",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "struct sigevent*", Name: "sevp"},
				{Type: "timer_t*", Name: "timer_id"},
			},
		},
		TimerSettime: {
			id32Bit: sys32timer_settime64,
			name:    "timer_settime",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
				{Type: "int", Name: "flags"},
				{Type: "const struct itimerspec*", Name: "new_value"},
				{Type: "struct itimerspec*", Name: "old_value"},
			},
		},
		TimerGettime: {
			id32Bit: sys32timer_gettime64,
			name:    "timer_gettime",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
				{Type: "struct itimerspec*", Name: "curr_value"},
			},
		},
		TimerGetoverrun: {
			id32Bit: sys32timer_getoverrun,
			name:    "timer_getoverrun",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
			},
		},
		TimerDelete: {
			id32Bit: sys32timer_delete,
			name:    "timer_delete",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
			},
		},
		ClockSettime: {
			id32Bit: sys32clock_settime64,
			name:    "clock_settime",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_clock"},
			params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "const struct timespec*", Name: "tp"},
			},
		},
		ClockGettime: {
			id32Bit: sys32clock_gettime64,
			name:    "clock_gettime",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_clock"},
			params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "struct timespec*", Name: "tp"},
			},
		},
		ClockGetres: {
			id32Bit: sys32clock_getres_time64,
			name:    "clock_getres",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_clock"},
			params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "struct timespec*", Name: "res"},
			},
		},
		ClockNanosleep: {
			id32Bit: sys32clock_nanosleep_time64,
			name:    "clock_nanosleep",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_clock"},
			params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clockid"},
				{Type: "int", Name: "flags"},
				{Type: "const struct timespec*", Name: "request"},
				{Type: "struct timespec*", Name: "remain"},
			},
		},
		ExitGroup: {
			id32Bit: sys32exit_group,
			name:    "exit_group",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "status"},
			},
		},
		EpollWait: {
			id32Bit: sys32epoll_wait,
			name:    "epoll_wait",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "epfd"},
				{Type: "struct epoll_event*", Name: "events"},
				{Type: "int", Name: "maxevents"},
				{Type: "int", Name: "timeout"},
			},
		},
		EpollCtl: {
			id32Bit: sys32epoll_ctl,
			name:    "epoll_ctl",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "epfd"},
				{Type: "int", Name: "op"},
				{Type: "int", Name: "fd"},
				{Type: "struct epoll_event*", Name: "event"},
			},
		},
		Tgkill: {
			id32Bit: sys32tgkill,
			name:    "tgkill",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "tgid"},
				{Type: "int", Name: "tid"},
				{Type: "int", Name: "sig"},
			},
		},
		Utimes: {
			id32Bit: sys32utimes,
			name:    "utimes",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "char*", Name: "filename"},
				{Type: "struct timeval*", Name: "times"},
			},
		},
		Vserver: {
			id32Bit: sys32vserver,
			name:    "vserver",
			syscall: true,
			sets:    []string{"syscalls"},
			params:  []trace.ArgMeta{},
		},
		Mbind: {
			id32Bit: sys32mbind,
			name:    "mbind",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_numa"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "unsigned long", Name: "len"},
				{Type: "int", Name: "mode"},
				{Type: "const unsigned long*", Name: "nodemask"},
				{Type: "unsigned long", Name: "maxnode"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		SetMempolicy: {
			id32Bit: sys32set_mempolicy,
			name:    "set_mempolicy",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_numa"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "mode"},
				{Type: "const unsigned long*", Name: "nodemask"},
				{Type: "unsigned long", Name: "maxnode"},
			},
		},
		GetMempolicy: {
			id32Bit: sys32get_mempolicy,
			name:    "get_mempolicy",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_numa"},
			params: []trace.ArgMeta{
				{Type: "int*", Name: "mode"},
				{Type: "unsigned long*", Name: "nodemask"},
				{Type: "unsigned long", Name: "maxnode"},
				{Type: "void*", Name: "addr"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		MqOpen: {
			id32Bit: sys32mq_open,
			name:    "mq_open",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "int", Name: "oflag"},
				{Type: "mode_t", Name: "mode"},
				{Type: "struct mq_attr*", Name: "attr"},
			},
		},
		MqUnlink: {
			id32Bit: sys32mq_unlink,
			name:    "mq_unlink",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
			},
		},
		MqTimedsend: {
			id32Bit: sys32mq_timedsend_time64,
			name:    "mq_timedsend",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "const char*", Name: "msg_ptr"},
				{Type: "size_t", Name: "msg_len"},
				{Type: "unsigned int", Name: "msg_prio"},
				{Type: "const struct timespec*", Name: "abs_timeout"},
			},
		},
		MqTimedreceive: {
			id32Bit: sys32mq_timedreceive_time64,
			name:    "mq_timedreceive",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "char*", Name: "msg_ptr"},
				{Type: "size_t", Name: "msg_len"},
				{Type: "unsigned int*", Name: "msg_prio"},
				{Type: "const struct timespec*", Name: "abs_timeout"},
			},
		},
		MqNotify: {
			id32Bit: sys32mq_notify,
			name:    "mq_notify",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "const struct sigevent*", Name: "sevp"},
			},
		},
		MqGetsetattr: {
			id32Bit: sys32mq_getsetattr,
			name:    "mq_getsetattr",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_msgq"},
			params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "const struct mq_attr*", Name: "newattr"},
				{Type: "struct mq_attr*", Name: "oldattr"},
			},
		},
		KexecLoad: {
			id32Bit: sys32kexec_load,
			name:    "kexec_load",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "entry"},
				{Type: "unsigned long", Name: "nr_segments"},
				{Type: "struct kexec_segment*", Name: "segments"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		Waitid: {
			id32Bit: sys32waitid,
			name:    "waitid",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "idtype"},
				{Type: "pid_t", Name: "id"},
				{Type: "struct siginfo*", Name: "infop"},
				{Type: "int", Name: "options"},
				{Type: "struct rusage*", Name: "rusage"},
			},
		},
		AddKey: {
			id32Bit: sys32add_key,
			name:    "add_key",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_keys"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "type"},
				{Type: "const char*", Name: "description"},
				{Type: "const void*", Name: "payload"},
				{Type: "size_t", Name: "plen"},
				{Type: "key_serial_t", Name: "keyring"},
			},
		},
		RequestKey: {
			id32Bit: sys32request_key,
			name:    "request_key",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_keys"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "type"},
				{Type: "const char*", Name: "description"},
				{Type: "const char*", Name: "callout_info"},
				{Type: "key_serial_t", Name: "dest_keyring"},
			},
		},
		Keyctl: {
			id32Bit: sys32keyctl,
			name:    "keyctl",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_keys"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "operation"},
				{Type: "unsigned long", Name: "arg2"},
				{Type: "unsigned long", Name: "arg3"},
				{Type: "unsigned long", Name: "arg4"},
				{Type: "unsigned long", Name: "arg5"},
			},
		},
		IoprioSet: {
			id32Bit: sys32ioprio_set,
			name:    "ioprio_set",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
				{Type: "int", Name: "ioprio"},
			},
		},
		IoprioGet: {
			id32Bit: sys32ioprio_get,
			name:    "ioprio_get",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "which"},
				{Type: "int", Name: "who"},
			},
		},
		InotifyInit: {
			id32Bit: sys32inotify_init,
			name:    "inotify_init",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_monitor"},
			params:  []trace.ArgMeta{},
		},
		InotifyAddWatch: {
			id32Bit: sys32inotify_add_watch,
			name:    "inotify_add_watch",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_monitor"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "u32", Name: "mask"},
			},
		},
		InotifyRmWatch: {
			id32Bit: sys32inotify_rm_watch,
			name:    "inotify_rm_watch",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_monitor"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "wd"},
			},
		},
		MigratePages: {
			id32Bit: sys32migrate_pages,
			name:    "migrate_pages",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_numa"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "pid"},
				{Type: "unsigned long", Name: "maxnode"},
				{Type: "const unsigned long*", Name: "old_nodes"},
				{Type: "const unsigned long*", Name: "new_nodes"},
			},
		},
		Openat: {
			id32Bit: sys32openat,
			name:    "openat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Mkdirat: {
			id32Bit: sys32mkdirat,
			name:    "mkdirat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_dir_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		Mknodat: {
			id32Bit: sys32mknodat,
			name:    "mknodat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
				{Type: "dev_t", Name: "dev"},
			},
		},
		Fchownat: {
			id32Bit: sys32fchownat,
			name:    "fchownat",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "uid_t", Name: "owner"},
				{Type: "gid_t", Name: "group"},
				{Type: "int", Name: "flags"},
			},
		},
		Futimesat: {
			id32Bit: sys32futimesat,
			name:    "futimesat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct timeval*", Name: "times"},
			},
		},
		Newfstatat: {
			id32Bit: sys32fstatat64,
			name:    "newfstatat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat*", Name: "statbuf"},
				{Type: "int", Name: "flags"},
			},
		},
		Unlinkat: {
			id32Bit: sys32unlinkat,
			name:    "unlinkat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_link_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
			},
		},
		Renameat: {
			id32Bit: sys32renameat,
			name:    "renameat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "olddirfd"},
				{Type: "const char*", Name: "oldpath"},
				{Type: "int", Name: "newdirfd"},
				{Type: "const char*", Name: "newpath"},
			},
		},
		Linkat: {
			id32Bit: sys32linkat,
			name:    "linkat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_link_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "olddirfd"},
				{Type: "const char*", Name: "oldpath"},
				{Type: "int", Name: "newdirfd"},
				{Type: "const char*", Name: "newpath"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Symlinkat: {
			id32Bit: sys32symlinkat,
			name:    "symlinkat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_link_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "target"},
				{Type: "int", Name: "newdirfd"},
				{Type: "const char*", Name: "linkpath"},
			},
		},
		Readlinkat: {
			id32Bit: sys32readlinkat,
			name:    "readlinkat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_link_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "char*", Name: "buf"},
				{Type: "int", Name: "bufsiz"},
			},
		},
		Fchmodat: {
			id32Bit: sys32fchmodat,
			name:    "fchmodat",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "mode_t", Name: "mode"},
				{Type: "int", Name: "flags"},
			},
		},
		Faccessat: {
			id32Bit: sys32faccessat,
			name:    "faccessat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "mode"},
				{Type: "int", Name: "flags"},
			},
		},
		Pselect6: {
			id32Bit: sys32pselect6_time64,
			name:    "pselect6",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "nfds"},
				{Type: "fd_set*", Name: "readfds"},
				{Type: "fd_set*", Name: "writefds"},
				{Type: "fd_set*", Name: "exceptfds"},
				{Type: "struct timespec*", Name: "timeout"},
				{Type: "void*", Name: "sigmask"},
			},
		},
		Ppoll: {
			id32Bit: sys32ppoll_time64,
			name:    "ppoll",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "struct pollfd*", Name: "fds"},
				{Type: "unsigned int", Name: "nfds"},
				{Type: "struct timespec*", Name: "tmo_p"},
				{Type: "const sigset_t*", Name: "sigmask"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		Unshare: {
			id32Bit: sys32unshare,
			name:    "unshare",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		SetRobustList: {
			id32Bit: sys32set_robust_list,
			name:    "set_robust_list",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_futex"},
			params: []trace.ArgMeta{
				{Type: "struct robust_list_head*", Name: "head"},
				{Type: "size_t", Name: "len"},
			},
		},
		GetRobustList: {
			id32Bit: sys32get_robust_list,
			name:    "get_robust_list",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_futex"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "pid"},
				{Type: "struct robust_list_head**", Name: "head_ptr"},
				{Type: "size_t*", Name: "len_ptr"},
			},
		},
		Splice: {
			id32Bit: sys32splice,
			name:    "splice",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd_in"},
				{Type: "off_t*", Name: "off_in"},
				{Type: "int", Name: "fd_out"},
				{Type: "off_t*", Name: "off_out"},
				{Type: "size_t", Name: "len"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Tee: {
			id32Bit: sys32tee,
			name:    "tee",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd_in"},
				{Type: "int", Name: "fd_out"},
				{Type: "size_t", Name: "len"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		SyncFileRange: {
			id32Bit: sys32sync_file_range,
			name:    "sync_file_range",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_sync"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "offset"},
				{Type: "off_t", Name: "nbytes"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Vmsplice: {
			id32Bit: sys32vmsplice,
			name:    "vmsplice",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "nr_segs"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		MovePages: {
			id32Bit: sys32move_pages,
			name:    "move_pages",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_numa"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "pid"},
				{Type: "unsigned long", Name: "count"},
				{Type: "const void**", Name: "pages"},
				{Type: "const int*", Name: "nodes"},
				{Type: "int*", Name: "status"},
				{Type: "int", Name: "flags"},
			},
		},
		Utimensat: {
			id32Bit: sys32utimensat_time64,
			name:    "utimensat",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct timespec*", Name: "times"},
				{Type: "int", Name: "flags"},
			},
		},
		EpollPwait: {
			id32Bit: sys32epoll_pwait,
			name:    "epoll_pwait",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "epfd"},
				{Type: "struct epoll_event*", Name: "events"},
				{Type: "int", Name: "maxevents"},
				{Type: "int", Name: "timeout"},
				{Type: "const sigset_t*", Name: "sigmask"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		Signalfd: {
			id32Bit: sys32signalfd,
			name:    "signalfd",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "sigset_t*", Name: "mask"},
				{Type: "int", Name: "flags"},
			},
		},
		TimerfdCreate: {
			id32Bit: sys32timerfd_create,
			name:    "timerfd_create",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "clockid"},
				{Type: "int", Name: "flags"},
			},
		},
		Eventfd: {
			id32Bit: sys32eventfd,
			name:    "eventfd",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "initval"},
				{Type: "int", Name: "flags"},
			},
		},
		Fallocate: {
			id32Bit: sys32fallocate,
			name:    "fallocate",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "mode"},
				{Type: "off_t", Name: "offset"},
				{Type: "off_t", Name: "len"},
			},
		},
		TimerfdSettime: {
			id32Bit: sys32timerfd_settime64,
			name:    "timerfd_settime",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "flags"},
				{Type: "const struct itimerspec*", Name: "new_value"},
				{Type: "struct itimerspec*", Name: "old_value"},
			},
		},
		TimerfdGettime: {
			id32Bit: sys32timerfd_gettime64,
			name:    "timerfd_gettime",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_timer"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct itimerspec*", Name: "curr_value"},
			},
		},
		Accept4: {
			id32Bit: sys32accept4,
			name:    "accept4",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "addr"},
				{Type: "int*", Name: "addrlen"},
				{Type: "int", Name: "flags"},
			},
		},
		Signalfd4: {
			id32Bit: sys32signalfd4,
			name:    "signalfd4",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const sigset_t*", Name: "mask"},
				{Type: "size_t", Name: "sizemask"},
				{Type: "int", Name: "flags"},
			},
		},
		Eventfd2: {
			id32Bit: sys32eventfd2,
			name:    "eventfd2",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "initval"},
				{Type: "int", Name: "flags"},
			},
		},
		EpollCreate1: {
			id32Bit: sys32epoll_create1,
			name:    "epoll_create1",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		Dup3: {
			id32Bit: sys32dup3,
			name:    "dup3",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_fd_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "oldfd"},
				{Type: "int", Name: "newfd"},
				{Type: "int", Name: "flags"},
			},
		},
		Pipe2: {
			id32Bit: sys32pipe2,
			name:    "pipe2",
			syscall: true,
			sets:    []string{"syscalls", "ipc", "ipc_pipe"},
			params: []trace.ArgMeta{
				{Type: "int[2]", Name: "pipefd"},
				{Type: "int", Name: "flags"},
			},
		},
		InotifyInit1: {
			id32Bit: sys32inotify_init1,
			name:    "inotify_init1",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_monitor"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		Preadv: {
			id32Bit: sys32preadv,
			name:    "preadv",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "iovcnt"},
				{Type: "unsigned long", Name: "pos_l"},
				{Type: "unsigned long", Name: "pos_h"},
			},
		},
		Pwritev: {
			id32Bit: sys32pwritev,
			name:    "pwritev",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "iovcnt"},
				{Type: "unsigned long", Name: "pos_l"},
				{Type: "unsigned long", Name: "pos_h"},
			},
		},
		RtTgsigqueueinfo: {
			id32Bit: sys32rt_tgsigqueueinfo,
			name:    "rt_tgsigqueueinfo",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "tgid"},
				{Type: "pid_t", Name: "tid"},
				{Type: "int", Name: "sig"},
				{Type: "siginfo_t*", Name: "info"},
			},
		},
		PerfEventOpen: {
			id32Bit: sys32perf_event_open,
			name:    "perf_event_open",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "struct perf_event_attr*", Name: "attr"},
				{Type: "pid_t", Name: "pid"},
				{Type: "int", Name: "cpu"},
				{Type: "int", Name: "group_fd"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		Recvmmsg: {
			id32Bit: sys32recvmmsg_time64,
			name:    "recvmmsg",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_snd_rcv"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct mmsghdr*", Name: "msgvec"},
				{Type: "unsigned int", Name: "vlen"},
				{Type: "int", Name: "flags"},
				{Type: "struct timespec*", Name: "timeout"},
			},
		},
		FanotifyInit: {
			id32Bit: sys32fanotify_init,
			name:    "fanotify_init",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_monitor"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "flags"},
				{Type: "unsigned int", Name: "event_f_flags"},
			},
		},
		FanotifyMark: {
			id32Bit: sys32fanotify_mark,
			name:    "fanotify_mark",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_monitor"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fanotify_fd"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "u64", Name: "mask"},
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
			},
		},
		Prlimit64: {
			id32Bit: sys32prlimit64,
			name:    "prlimit64",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int", Name: "resource"},
				{Type: "const struct rlimit64*", Name: "new_limit"},
				{Type: "struct rlimit64*", Name: "old_limit"},
			},
		},
		NameToHandleAt: {
			id32Bit: sys32name_to_handle_at,
			name:    "name_to_handle_at",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct file_handle*", Name: "handle"},
				{Type: "int*", Name: "mount_id"},
				{Type: "int", Name: "flags"},
			},
		},
		OpenByHandleAt: {
			id32Bit: sys32open_by_handle_at,
			name:    "open_by_handle_at",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "mount_fd"},
				{Type: "struct file_handle*", Name: "handle"},
				{Type: "int", Name: "flags"},
			},
		},
		ClockAdjtime: {
			id32Bit: sys32clock_adjtime,
			name:    "clock_adjtime",
			syscall: true,
			sets:    []string{"syscalls", "time", "time_clock"},
			params: []trace.ArgMeta{
				{Type: "const clockid_t", Name: "clk_id"},
				{Type: "struct timex*", Name: "buf"},
			},
		},
		Syncfs: {
			id32Bit: sys32syncfs,
			name:    "syncfs",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_sync"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
			},
		},
		Sendmmsg: {
			id32Bit: sys32sendmmsg,
			name:    "sendmmsg",
			syscall: true,
			sets:    []string{"syscalls", "net", "net_snd_rcv"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct mmsghdr*", Name: "msgvec"},
				{Type: "unsigned int", Name: "vlen"},
				{Type: "int", Name: "flags"},
			},
		},
		Setns: {
			id32Bit: sys32setns,
			name:    "setns",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "nstype"},
			},
		},
		Getcpu: {
			id32Bit: sys32getcpu,
			name:    "getcpu",
			syscall: true,
			sets:    []string{"syscalls", "system", "system_numa"},
			params: []trace.ArgMeta{
				{Type: "unsigned int*", Name: "cpu"},
				{Type: "unsigned int*", Name: "node"},
				{Type: "struct getcpu_cache*", Name: "tcache"},
			},
		},
		ProcessVmReadv: {
			id32Bit: sys32process_vm_readv,
			name:    "process_vm_readv",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "const struct iovec*", Name: "local_iov"},
				{Type: "unsigned long", Name: "liovcnt"},
				{Type: "const struct iovec*", Name: "remote_iov"},
				{Type: "unsigned long", Name: "riovcnt"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		ProcessVmWritev: {
			id32Bit: sys32process_vm_writev,
			name:    "process_vm_writev",
			syscall: true,
			sets:    []string{"default", "syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "const struct iovec*", Name: "local_iov"},
				{Type: "unsigned long", Name: "liovcnt"},
				{Type: "const struct iovec*", Name: "remote_iov"},
				{Type: "unsigned long", Name: "riovcnt"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		Kcmp: {
			id32Bit: sys32kcmp,
			name:    "kcmp",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid1"},
				{Type: "pid_t", Name: "pid2"},
				{Type: "int", Name: "type"},
				{Type: "unsigned long", Name: "idx1"},
				{Type: "unsigned long", Name: "idx2"},
			},
		},
		FinitModule: {
			id32Bit: sys32finit_module,
			name:    "finit_module",
			syscall: true,
			sets:    []string{"default", "syscalls", "system", "system_module"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "param_values"},
				{Type: "int", Name: "flags"},
			},
		},
		SchedSetattr: {
			id32Bit: sys32sched_setattr,
			name:    "sched_setattr",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct sched_attr*", Name: "attr"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		SchedGetattr: {
			id32Bit: sys32sched_getattr,
			name:    "sched_getattr",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_sched"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct sched_attr*", Name: "attr"},
				{Type: "unsigned int", Name: "size"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Renameat2: {
			id32Bit: sys32renameat2,
			name:    "renameat2",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "olddirfd"},
				{Type: "const char*", Name: "oldpath"},
				{Type: "int", Name: "newdirfd"},
				{Type: "const char*", Name: "newpath"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Seccomp: {
			id32Bit: sys32seccomp,
			name:    "seccomp",
			syscall: true,
			sets:    []string{"syscalls", "proc"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "operation"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "const void*", Name: "args"},
			},
		},
		Getrandom: {
			id32Bit: sys32getrandom,
			name:    "getrandom",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "buflen"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		MemfdCreate: {
			id32Bit: sys32memfd_create,
			name:    "memfd_create",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		KexecFileLoad: {
			id32Bit: sys32undefined,
			name:    "kexec_file_load",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "kernel_fd"},
				{Type: "int", Name: "initrd_fd"},
				{Type: "unsigned long", Name: "cmdline_len"},
				{Type: "const char*", Name: "cmdline"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		Bpf: {
			id32Bit: sys32bpf,
			name:    "bpf",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "cmd"},
				{Type: "union bpf_attr*", Name: "attr"},
				{Type: "unsigned int", Name: "size"},
			},
		},
		Execveat: {
			id32Bit: sys32execveat,
			name:    "execveat",
			syscall: true,
			dependencies: Dependencies{
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_tails",
						"syscall__execveat",
						[]uint32{uint32(Execveat)},
					),
				},
			},
			sets: []string{"syscalls", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "const char*const*", Name: "argv"},
				{Type: "const char*const*", Name: "envp"},
				{Type: "int", Name: "flags"},
			},
		},
		Userfaultfd: {
			id32Bit: sys32userfaultfd,
			name:    "userfaultfd",
			syscall: true,
			sets:    []string{"syscalls", "system"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "flags"},
			},
		},
		Membarrier: {
			id32Bit: sys32membarrier,
			name:    "membarrier",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "cmd"},
				{Type: "int", Name: "flags"},
			},
		},
		Mlock2: {
			id32Bit: sys32mlock2,
			name:    "mlock2",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "const void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "flags"},
			},
		},
		CopyFileRange: {
			id32Bit: sys32copy_file_range,
			name:    "copy_file_range",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd_in"},
				{Type: "off_t*", Name: "off_in"},
				{Type: "int", Name: "fd_out"},
				{Type: "off_t*", Name: "off_out"},
				{Type: "size_t", Name: "len"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Preadv2: {
			id32Bit: sys32preadv2,
			name:    "preadv2",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "iovcnt"},
				{Type: "unsigned long", Name: "pos_l"},
				{Type: "unsigned long", Name: "pos_h"},
				{Type: "int", Name: "flags"},
			},
		},
		Pwritev2: {
			id32Bit: sys32pwritev2,
			name:    "pwritev2",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const struct iovec*", Name: "iov"},
				{Type: "unsigned long", Name: "iovcnt"},
				{Type: "unsigned long", Name: "pos_l"},
				{Type: "unsigned long", Name: "pos_h"},
				{Type: "int", Name: "flags"},
			},
		},
		PkeyMprotect: {
			id32Bit: sys32pkey_mprotect,
			name:    "pkey_mprotect",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "prot"},
				{Type: "int", Name: "pkey"},
			},
		},
		PkeyAlloc: {
			id32Bit: sys32pkey_alloc,
			name:    "pkey_alloc",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "flags"},
				{Type: "unsigned long", Name: "access_rights"},
			},
		},
		PkeyFree: {
			id32Bit: sys32pkey_free,
			name:    "pkey_free",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "pkey"},
			},
		},
		Statx: {
			id32Bit: sys32statx,
			name:    "statx",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "unsigned int", Name: "mask"},
				{Type: "struct statx*", Name: "statxbuf"},
			},
		},
		IoPgetevents: {
			id32Bit: sys32io_pgetevents_time64,
			name:    "io_pgetevents",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_async_io"},
			params: []trace.ArgMeta{
				{Type: "aio_context_t", Name: "ctx_id"},
				{Type: "long", Name: "min_nr"},
				{Type: "long", Name: "nr"},
				{Type: "struct io_event*", Name: "events"},
				{Type: "struct timespec*", Name: "timeout"},
				{Type: "const struct __aio_sigset*", Name: "usig"},
			},
		},
		Rseq: {
			id32Bit: sys32rseq,
			name:    "rseq",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "struct rseq*", Name: "rseq"},
				{Type: "u32", Name: "rseq_len"},
				{Type: "int", Name: "flags"},
				{Type: "u32", Name: "sig"},
			},
		},
		PidfdSendSignal: {
			id32Bit: sys32pidfd_send_signal,
			name:    "pidfd_send_signal",
			syscall: true,
			sets:    []string{"syscalls", "signals"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "pidfd"},
				{Type: "int", Name: "sig"},
				{Type: "siginfo_t*", Name: "info"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		IoUringSetup: {
			id32Bit: sys32io_uring_setup,
			name:    "io_uring_setup",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "entries"},
				{Type: "struct io_uring_params*", Name: "p"},
			},
		},
		IoUringEnter: {
			id32Bit: sys32io_uring_enter,
			name:    "io_uring_enter",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "unsigned int", Name: "to_submit"},
				{Type: "unsigned int", Name: "min_complete"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "sigset_t*", Name: "sig"},
			},
		},
		IoUringRegister: {
			id32Bit: sys32io_uring_register,
			name:    "io_uring_register",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "unsigned int", Name: "opcode"},
				{Type: "void*", Name: "arg"},
				{Type: "unsigned int", Name: "nr_args"},
			},
		},
		OpenTree: {
			id32Bit: sys32open_tree,
			name:    "open_tree",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dfd"},
				{Type: "const char*", Name: "filename"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		MoveMount: {
			id32Bit: sys32move_mount,
			name:    "move_mount",
			syscall: true,
			sets:    []string{"default", "syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "from_dfd"},
				{Type: "const char*", Name: "from_path"},
				{Type: "int", Name: "to_dfd"},
				{Type: "const char*", Name: "to_path"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Fsopen: {
			id32Bit: sys32fsopen,
			name:    "fsopen",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "fsname"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Fsconfig: {
			id32Bit: sys32fsconfig,
			name:    "fsconfig",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "int*", Name: "fs_fd"},
				{Type: "unsigned int", Name: "cmd"},
				{Type: "const char*", Name: "key"},
				{Type: "const void*", Name: "value"},
				{Type: "int", Name: "aux"},
			},
		},
		Fsmount: {
			id32Bit: sys32fsmount,
			name:    "fsmount",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fsfd"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "unsigned int", Name: "ms_flags"},
			},
		},
		Fspick: {
			id32Bit: sys32fspick,
			name:    "fspick",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		PidfdOpen: {
			id32Bit: sys32pidfd_open,
			name:    "pidfd_open",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Clone3: {
			id32Bit: sys32clone3,
			name:    "clone3",
			syscall: true,
			sets:    []string{"syscalls", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "struct clone_args*", Name: "cl_args"},
				{Type: "size_t", Name: "size"},
			},
		},
		CloseRange: {
			id32Bit: sys32close_range,
			name:    "close_range",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "first"},
				{Type: "unsigned int", Name: "last"},
			},
		},
		Openat2: {
			id32Bit: sys32openat2,
			name:    "openat2",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dirfd"},
				{Type: "const char*", Name: "pathname"},
				{Type: "struct open_how*", Name: "how"},
				{Type: "size_t", Name: "size"},
			},
		},
		PidfdGetfd: {
			id32Bit: sys32pidfd_getfd,
			name:    "pidfd_getfd",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "pidfd"},
				{Type: "int", Name: "targetfd"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Faccessat2: {
			id32Bit: sys32faccessat2,
			name:    "faccessat2",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_attr"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "const char*", Name: "path"},
				{Type: "int", Name: "mode"},
				{Type: "int", Name: "flag"},
			},
		},
		ProcessMadvise: {
			id32Bit: sys32process_madvise,
			name:    "process_madvise",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "pidfd"},
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "length"},
				{Type: "int", Name: "advice"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		EpollPwait2: {
			id32Bit: sys32epoll_pwait2,
			name:    "epoll_pwait2",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_mux_io"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct epoll_event*", Name: "events"},
				{Type: "int", Name: "maxevents"},
				{Type: "const struct timespec*", Name: "timeout"},
				{Type: "const sigset_t*", Name: "sigset"},
			},
		},
		MountSetatt: {
			id32Bit: sys32mount_setattr,
			name:    "mount_setattr",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "dfd"},
				{Type: "char*", Name: "path"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "struct mount_attr*", Name: "uattr"},
				{Type: "size_t", Name: "usize"},
			},
		},
		QuotactlFd: {
			id32Bit: sys32quotactl_fd,
			name:    "quotactl_fd",
			syscall: true,
			sets:    []string{"syscalls", "fs"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "unsigned int", Name: "cmd"},
				{Type: "qid_t", Name: "id"},
				{Type: "void *", Name: "addr"},
			},
		},
		LandlockCreateRuleset: {
			id32Bit: sys32landlock_create_ruleset,
			name:    "landlock_create_ruleset",
			syscall: true,
			sets:    []string{"syscalls", "proc", "fs"},
			params: []trace.ArgMeta{
				{Type: "struct landlock_ruleset_attr*", Name: "attr"},
				{Type: "size_t", Name: "size"},
				{Type: "u32", Name: "flags"},
			},
		},
		LandlockAddRule: {
			id32Bit: sys32landlock_add_rule,
			name:    "landlock_add_rule",
			syscall: true,
			sets:    []string{"syscalls", "proc", "fs"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "ruleset_fd"},
				{Type: "landlock_rule_type", Name: "rule_type"},
				{Type: "void*", Name: "rule_attr"},
				{Type: "u32", Name: "flags"},
			},
		},
		LandloclRestrictSet: {
			id32Bit: sys32landlock_restrict_self,
			name:    "landlock_restrict_self",
			syscall: true,
			sets:    []string{"syscalls", "proc", "fs"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "ruleset_fd"},
				{Type: "u32", Name: "flags"},
			},
		},
		MemfdSecret: {
			id32Bit: sys32memfd_secret,
			name:    "memfd_secret",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "flags"},
			},
		},
		ProcessMrelease: {
			id32Bit: sys32process_mrelease,
			name:    "process_mrelease",
			syscall: true,
			sets:    []string{"syscalls"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "pidfd"},
				{Type: "unsigned int", Name: "flags"},
			},
		},
		Waitpid: {
			id32Bit: sys32waitpid,
			name:    "waitpid",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "int*", Name: "status"},
				{Type: "int", Name: "options"},
			},
		},
		Oldfstat: {
			id32Bit: sys32oldfstat,
			name:    "oldfstat",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Break: {
			id32Bit: sys32break,
			name:    "break",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Oldstat: {
			id32Bit: sys32oldstat,
			name:    "oldstat",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "char*", Name: "filename"},
				{Type: "struct __old_kernel_stat*", Name: "statbuf"},
			},
		},
		Umount: {
			id32Bit: sys32umount,
			name:    "umount",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "target"},
			},
		},
		Stime: {
			id32Bit: sys32stime,
			name:    "stime",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const time_t*", Name: "t"},
			},
		},
		Stty: {
			id32Bit: sys32stty,
			name:    "stty",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Gtty: {
			id32Bit: sys32gtty,
			name:    "gtty",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Nice: {
			id32Bit: sys32nice,
			name:    "nice",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "inc"},
			},
		},
		Ftime: {
			id32Bit: sys32ftime,
			name:    "ftime",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Prof: {
			id32Bit: sys32prof,
			name:    "prof",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Signal: {
			id32Bit: sys32signal,
			name:    "signal",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "signum"},
				{Type: "sighandler_t", Name: "handler"},
			},
		},
		Lock: {
			id32Bit: sys32lock,
			name:    "lock",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Mpx: {
			id32Bit: sys32mpx,
			name:    "mpx",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Ulimit: {
			id32Bit: sys32ulimit,
			name:    "ulimit",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Oldolduname: {
			id32Bit: sys32oldolduname,
			name:    "oldolduname",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "struct oldold_utsname*", Name: "name"},
			},
		},
		Sigaction: {
			id32Bit: sys32sigaction,
			name:    "sigaction",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sig"},
				{Type: "const struct sigaction*", Name: "act"},
				{Type: "struct sigaction*", Name: "oact"},
			},
		},
		Sgetmask: {
			id32Bit: sys32sgetmask,
			name:    "sgetmask",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Ssetmask: {
			id32Bit: sys32ssetmask,
			name:    "ssetmask",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "long", Name: "newmask"},
			},
		},
		Sigsuspend: {
			id32Bit: sys32sigsuspend,
			name:    "sigsuspend",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const sigset_t*", Name: "mask"},
			},
		},
		Sigpending: {
			id32Bit: sys32sigpending,
			name:    "sigpending",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "sigset_t*", Name: "set"},
			},
		},
		Oldlstat: {
			id32Bit: sys32oldlstat,
			name:    "oldlstat",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat*", Name: "statbuf"},
			},
		},
		Readdir: {
			id32Bit: sys32readdir,
			name:    "readdir",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "struct old_linux_dirent*", Name: "dirp"},
				{Type: "unsigned int", Name: "count"},
			},
		},
		Profil: {
			id32Bit: sys32profil,
			name:    "profil",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Socketcall: {
			id32Bit: sys32socketcall,
			name:    "socketcall",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "call"},
				{Type: "unsigned long*", Name: "args"},
			},
		},
		Olduname: {
			id32Bit: sys32olduname,
			name:    "olduname",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "struct utsname*", Name: "buf"},
			},
		},
		Idle: {
			id32Bit: sys32idle,
			name:    "idle",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Vm86old: {
			id32Bit: sys32vm86old,
			name:    "vm86old",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "struct vm86_struct*", Name: "info"},
			},
		},
		Ipc: {
			id32Bit: sys32ipc,
			name:    "ipc",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "call"},
				{Type: "int", Name: "first"},
				{Type: "unsigned long", Name: "second"},
				{Type: "unsigned long", Name: "third"},
				{Type: "void*", Name: "ptr"},
				{Type: "long", Name: "fifth"},
			},
		},
		Sigreturn: {
			id32Bit: sys32sigreturn,
			name:    "sigreturn",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Sigprocmask: {
			id32Bit: sys32sigprocmask,
			name:    "sigprocmask",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "how"},
				{Type: "const sigset_t *restrict", Name: "set"},
				{Type: "sigset_t *restrict", Name: "oldset"},
			},
		},
		Bdflush: {
			id32Bit: sys32bdflush,
			name:    "bdflush",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Afs_syscall: {
			id32Bit: sys32afs_syscall,
			name:    "afs_syscall",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Llseek: {
			id32Bit: sys32_llseek,
			name:    "llseek",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "unsigned long", Name: "offset_high"},
				{Type: "unsigned long", Name: "offset_low"},
				{Type: "loff_t*", Name: "result"},
				{Type: "unsigned int", Name: "whence"},
			},
		},
		OldSelect: {
			id32Bit: sys32select,
			name:    "old_select",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "nfds"},
				{Type: "fd_set*", Name: "readfds"},
				{Type: "fd_set*", Name: "writefds"},
				{Type: "fd_set*", Name: "exceptfds"},
				{Type: "struct timeval*", Name: "timeout"},
			},
		},
		Vm86: {
			id32Bit: sys32vm86,
			name:    "vm86",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "fn"},
				{Type: "struct vm86plus_struct*", Name: "v86"},
			},
		},
		OldGetrlimit: {
			id32Bit: sys32getrlimit,
			name:    "old_getrlimit",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "resource"},
				{Type: "struct rlimit*", Name: "rlim"},
			},
		},
		Mmap2: {
			id32Bit: sys32mmap2,
			name:    "mmap2",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "addr"},
				{Type: "unsigned long", Name: "length"},
				{Type: "unsigned long", Name: "prot"},
				{Type: "unsigned long", Name: "flags"},
				{Type: "unsigned long", Name: "fd"},
				{Type: "unsigned long", Name: "pgoffset"},
			},
		},
		Truncate64: {
			id32Bit: sys32truncate64,
			name:    "truncate64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "off_t", Name: "length"},
			},
		},
		Ftruncate64: {
			id32Bit: sys32ftruncate64,
			name:    "ftruncate64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "off_t", Name: "length"},
			},
		},
		Stat64: {
			id32Bit: sys32stat64,
			name:    "stat64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat64*", Name: "statbuf"},
			},
		},
		Lstat64: {
			id32Bit: sys32lstat64,
			name:    "lstat64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "struct stat64*", Name: "statbuf"},
			},
		},
		Fstat64: {
			id32Bit: sys32fstat64,
			name:    "fstat64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct stat64*", Name: "statbuf"},
			},
		},
		Lchown16: {
			id32Bit: sys32lchown,
			name:    "lchown16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "old_uid_t", Name: "owner"},
				{Type: "old_gid_t", Name: "group"},
			},
		},
		Getuid16: {
			id32Bit: sys32getuid,
			name:    "getuid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Getgid16: {
			id32Bit: sys32getgid,
			name:    "getgid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Geteuid16: {
			id32Bit: sys32geteuid,
			name:    "geteuid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Getegid16: {
			id32Bit: sys32getegid,
			name:    "getegid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		Setreuid16: {
			id32Bit: sys32setreuid,
			name:    "setreuid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_uid_t", Name: "ruid"},
				{Type: "old_uid_t", Name: "euid"},
			},
		},
		Setregid16: {
			id32Bit: sys32setregid,
			name:    "setregid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_gid_t", Name: "rgid"},
				{Type: "old_gid_t", Name: "egid"},
			},
		},
		Getgroups16: {
			id32Bit: sys32getgroups,
			name:    "getgroups16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "size"},
				{Type: "old_gid_t*", Name: "list"},
			},
		},
		Setgroups16: {
			id32Bit: sys32setgroups,
			name:    "setgroups16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "size_t", Name: "size"},
				{Type: "const gid_t*", Name: "list"},
			},
		},
		Fchown16: {
			id32Bit: sys32fchown,
			name:    "fchown16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "fd"},
				{Type: "old_uid_t", Name: "user"},
				{Type: "old_gid_t", Name: "group"},
			},
		},
		Setresuid16: {
			id32Bit: sys32setresuid,
			name:    "setresuid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_uid_t", Name: "ruid"},
				{Type: "old_uid_t", Name: "euid"},
				{Type: "old_uid_t", Name: "suid"},
			},
		},
		Getresuid16: {
			id32Bit: sys32getresuid,
			name:    "getresuid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_uid_t*", Name: "ruid"},
				{Type: "old_uid_t*", Name: "euid"},
				{Type: "old_uid_t*", Name: "suid"},
			},
		},
		Setresgid16: {
			id32Bit: sys32setresgid,
			name:    "setresgid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_uid_t", Name: "rgid"},
				{Type: "old_uid_t", Name: "euid"},
				{Type: "old_uid_t", Name: "suid"},
			},
		},
		Getresgid16: {
			id32Bit: sys32getresgid,
			name:    "getresgid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_gid_t*", Name: "rgid"},
				{Type: "old_gid_t*", Name: "egid"},
				{Type: "old_gid_t*", Name: "sgid"},
			},
		},
		Chown16: {
			id32Bit: sys32chown,
			name:    "chown16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "old_uid_t", Name: "owner"},
				{Type: "old_gid_t", Name: "group"},
			},
		},
		Setuid16: {
			id32Bit: sys32setuid,
			name:    "setuid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_old_uid_t", Name: "uid"},
			},
		},
		Setgid16: {
			id32Bit: sys32setgid,
			name:    "setgid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_gid_t", Name: "gid"},
			},
		},
		Setfsuid16: {
			id32Bit: sys32setfsuid,
			name:    "setfsuid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_uid_t", Name: "fsuid"},
			},
		},
		Setfsgid16: {
			id32Bit: sys32setfsgid,
			name:    "setfsgid16",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "old_gid_t", Name: "fsgid"},
			},
		},
		Fcntl64: {
			id32Bit: sys32fcntl64,
			name:    "fcntl64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "int", Name: "cmd"},
				{Type: "unsigned long", Name: "arg"},
			},
		},
		Sendfile32: {
			id32Bit: sys32sendfile,
			name:    "sendfile32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "out_fd"},
				{Type: "int", Name: "in_fd"},
				{Type: "off_t*", Name: "offset"},
				{Type: "size_t", Name: "count"},
			},
		},
		Statfs64: {
			id32Bit: sys32statfs64,
			name:    "statfs64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "size_t", Name: "sz"},
				{Type: "struct statfs64*", Name: "buf"},
			},
		},
		Fstatfs64: {
			id32Bit: sys32fstatfs64,
			name:    "fstatfs64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "size_t", Name: "sz"},
				{Type: "struct statfs64*", Name: "buf"},
			},
		},
		Fadvise64_64: {
			id32Bit: sys32fadvise64_64,
			name:    "fadvise64_64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "loff_t", Name: "offset"},
				{Type: "loff_t", Name: "len"},
				{Type: "int", Name: "advice"},
			},
		},
		ClockGettime32: {
			id32Bit: sys32clock_gettime,
			name:    "clock_gettime32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "clockid_t", Name: "which_clock"},
				{Type: "struct old_timespec32*", Name: "tp"},
			},
		},
		ClockSettime32: {
			id32Bit: sys32clock_settime,
			name:    "clock_settime32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "clockid_t", Name: "which_clock"},
				{Type: "struct old_timespec32*", Name: "tp"},
			},
		},
		ClockAdjtime64: {
			id32Bit: sys32clock_adjtime64,
			name:    "clock_adjtime64",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		ClockGetresTime32: {
			id32Bit: sys32clock_getres,
			name:    "clock_getres_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "clockid_t", Name: "which_clock"},
				{Type: "struct old_timespec32*", Name: "tp"},
			},
		},
		ClockNanosleepTime32: {
			id32Bit: sys32clock_nanosleep,
			name:    "clock_nanosleep_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "clockid_t", Name: "which_clock"},
				{Type: "int", Name: "flags"},
				{Type: "struct old_timespec32*", Name: "rqtp"},
				{Type: "struct old_timespec32*", Name: "rmtp"},
			},
		},
		TimerGettime32: {
			id32Bit: sys32timer_gettime,
			name:    "timer_gettime32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
				{Type: "struct old_itimerspec32*", Name: "setting"},
			},
		},
		TimerSettime32: {
			id32Bit: sys32timer_settime,
			name:    "timer_settime32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "timer_t", Name: "timer_id"},
				{Type: "int", Name: "flags"},
				{Type: "struct old_itimerspec32*", Name: "new"},
				{Type: "struct old_itimerspec32*", Name: "old"},
			},
		},
		TimerfdGettime32: {
			id32Bit: sys32timerfd_gettime,
			name:    "timerfd_gettime32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "ufd"},
				{Type: "struct old_itimerspec32*", Name: "otmr"},
			},
		},
		TimerfdSettime32: {
			id32Bit: sys32timerfd_settime,
			name:    "timerfd_settime32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "ufd"},
				{Type: "int", Name: "flags"},
				{Type: "struct old_itimerspec32*", Name: "utmr"},
				{Type: "struct old_itimerspec32*", Name: "otmr"},
			},
		},
		UtimensatTime32: {
			id32Bit: sys32utimensat,
			name:    "utimensat_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "dfd"},
				{Type: "char*", Name: "filename"},
				{Type: "struct old_timespec32*", Name: "t"},
				{Type: "int", Name: "flags"},
			},
		},
		Pselect6Time32: {
			id32Bit: sys32pselect6,
			name:    "pselect6_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "n"},
				{Type: "fd_set*", Name: "inp"},
				{Type: "fd_set*", Name: "outp"},
				{Type: "fd_set*", Name: "exp"},
				{Type: "struct old_timespec32*", Name: "tsp"},
				{Type: "void*", Name: "sig"},
			},
		},
		PpollTime32: {
			id32Bit: sys32ppoll,
			name:    "ppoll_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "struct pollfd*", Name: "ufds"},
				{Type: "unsigned int", Name: "nfds"},
				{Type: "struct old_timespec32*", Name: "tsp"},
				{Type: "sigset_t*", Name: "sigmask"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		IoPgeteventsTime32: {
			id32Bit: sys32io_pgetevents,
			name:    "io_pgetevents_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params:  []trace.ArgMeta{},
		},
		RecvmmsgTime32: {
			id32Bit: sys32recvmmsg,
			name:    "recvmmsg_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "fd"},
				{Type: "struct mmsghdr*", Name: "mmsg"},
				{Type: "unsigned int", Name: "vlen"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "struct old_timespec32*", Name: "timeout"},
			},
		},
		MqTimedsendTime32: {
			id32Bit: sys32mq_timedsend,
			name:    "mq_timedsend_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "char*", Name: "u_msg_ptr"},
				{Type: "unsigned int", Name: "msg_len"},
				{Type: "unsigned int", Name: "msg_prio"},
				{Type: "struct old_timespec32*", Name: "u_abs_timeout"},
			},
		},
		MqTimedreceiveTime32: {
			id32Bit: sys32mq_timedreceive,
			name:    "mq_timedreceive_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "mqd_t", Name: "mqdes"},
				{Type: "char*", Name: "u_msg_ptr"},
				{Type: "unsigned int", Name: "msg_len"},
				{Type: "unsigned int*", Name: "u_msg_prio"},
				{Type: "struct old_timespec32*", Name: "u_abs_timeout"},
			},
		},
		RtSigtimedwaitTime32: {
			id32Bit: sys32rt_sigtimedwait,
			name:    "rt_sigtimedwait_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "sigset_t*", Name: "uthese"},
				{Type: "siginfo_t*", Name: "uinfo"},
				{Type: "struct old_timespec32*", Name: "uts"},
				{Type: "size_t", Name: "sigsetsize"},
			},
		},
		FutexTime32: {
			id32Bit: sys32futex,
			name:    "futex_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "u32*", Name: "uaddr"},
				{Type: "int", Name: "op"},
				{Type: "u32", Name: "val"},
				{Type: "struct old_timespec32*", Name: "utime"},
				{Type: "u32*", Name: "uaddr2"},
				{Type: "u32", Name: "val3"},
			},
		},
		SchedRrGetInterval32: {
			id32Bit: sys32sched_rr_get_interval,
			name:    "sched_rr_get_interval_time32",
			syscall: true,
			sets:    []string{"syscalls", "32bit_unique"},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "struct old_timespec32*", Name: "interval"},
			},
		},
		SysEnter: {
			id32Bit: sys32undefined,
			name:    "sys_enter",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SysEnter, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "syscall"},
			},
		},
		SysExit: {
			id32Bit: sys32undefined,
			name:    "sys_exit",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SysExit, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "syscall"},
			},
		},
		SchedProcessFork: {
			id32Bit: sys32undefined,
			name:    "sched_process_fork",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SchedProcessFork, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "parent_tid"},
				{Type: "int", Name: "parent_ns_tid"},
				{Type: "int", Name: "parent_pid"},
				{Type: "int", Name: "parent_ns_pid"},
				{Type: "int", Name: "child_tid"},
				{Type: "int", Name: "child_ns_tid"},
				{Type: "int", Name: "child_pid"},
				{Type: "int", Name: "child_ns_pid"},
				{Type: "unsigned long", Name: "start_time"},
			},
		},
		SchedProcessExec: {
			id32Bit: sys32undefined,
			name:    "sched_process_exec",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SchedProcessExec, Required: true},
					{Handle: probes.LoadElfPhdrs, Required: false},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"prog_array_tp",
						"sched_process_exec_event_submit_tail",
						[]uint32{TailSchedProcessExecEventSubmit},
					),
				},
				Capabilities: Capabilities{
					capabilities.Base: []cap.Value{
						// 1. set by processSchedProcessFork IF ExecHash enabled
						// 2. set by processSchedProcessExec by CaptureExec if needed
						// cap.SYS_PTRACE,
					},
				},
			},
			sets: []string{"default", "proc"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "cmdpath"},
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "umode_t", Name: "inode_mode"},
				{Type: "const char*", Name: "interpreter_pathname"},
				{Type: "dev_t", Name: "interpreter_dev"},
				{Type: "unsigned long", Name: "interpreter_inode"},
				{Type: "unsigned long", Name: "interpreter_ctime"},
				{Type: "const char**", Name: "argv"},
				{Type: "const char*", Name: "interp"},
				{Type: "umode_t", Name: "stdin_type"},
				{Type: "char*", Name: "stdin_path"},
				{Type: "int", Name: "invoked_from_kernel"},
				{Type: "const char**", Name: "env"},
			},
		},
		SchedProcessExit: {
			id32Bit: sys32undefined,
			name:    "sched_process_exit",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SchedProcessExit, Required: true},
					{Handle: probes.SchedProcessFree, Required: true},
				},
			},
			sets: []string{"proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "long", Name: "exit_code"},
				// The field value represents that all threads exited at the event time.
				// Multiple exits of threads of the same process group at the same time could result that all threads exit
				// events would have 'true' value in this field altogether.
				{Type: "bool", Name: "process_group_exit"},
			},
		},
		SchedSwitch: {
			id32Bit: sys32undefined,
			name:    "sched_switch",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SchedSwitch, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "cpu"},
				{Type: "int", Name: "prev_tid"},
				{Type: "const char*", Name: "prev_comm"},
				{Type: "int", Name: "next_tid"},
				{Type: "const char*", Name: "next_comm"},
			},
		},
		DoExit: {
			id32Bit: sys32undefined,
			name:    "do_exit",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DoExit, Required: true},
				},
			},
			sets:   []string{"proc", "proc_life"},
			params: []trace.ArgMeta{},
		},
		CapCapable: {
			id32Bit: sys32undefined,
			name:    "cap_capable",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.CapCapable, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "cap"},
			},
		},
		VfsWrite: {
			id32Bit: sys32undefined,
			name:    "vfs_write",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.VfsWrite, Required: true},
					{Handle: probes.VfsWriteRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "pos"},
			},
		},
		VfsWritev: {
			id32Bit: sys32undefined,
			name:    "vfs_writev",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.VfsWriteV, Required: true},
					{Handle: probes.VfsWriteVRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "vlen"},
				{Type: "off_t", Name: "pos"},
			},
		},
		MemProtAlert: {
			id32Bit: sys32undefined,
			name:    "mem_prot_alert",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityMmapAddr, Required: true},
					{Handle: probes.SecurityFileMProtect, Required: true},
					{Handle: probes.SyscallEnter__Internal, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Mmap), uint32(Mprotect), uint32(PkeyMprotect)},
					),
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "u32", Name: "alert"},
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "prot"},
				{Type: "int", Name: "prev_prot"},
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "u64", Name: "ctime"},
			},
		},
		CommitCreds: {
			id32Bit: sys32undefined,
			name:    "commit_creds",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.CommitCreds, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "slim_cred_t", Name: "old_cred"},
				{Type: "slim_cred_t", Name: "new_cred"},
			},
		},
		SwitchTaskNS: {
			id32Bit: sys32undefined,
			name:    "switch_task_ns",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SwitchTaskNS, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "pid_t", Name: "pid"},
				{Type: "u32", Name: "new_mnt"},
				{Type: "u32", Name: "new_pid"},
				{Type: "u32", Name: "new_uts"},
				{Type: "u32", Name: "new_ipc"},
				{Type: "u32", Name: "new_net"},
				{Type: "u32", Name: "new_cgroup"},
			},
		},
		MagicWrite: {
			id32Bit: sys32undefined,
			name:    "magic_write",
			docPath: "security_alerts/magic_write.md",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.VfsWrite, Required: true},
					{Handle: probes.VfsWriteRet, Required: true},
					{Handle: probes.VfsWriteV, Required: false},
					{Handle: probes.VfsWriteVRet, Required: false},
					{Handle: probes.KernelWrite, Required: false},
					{Handle: probes.KernelWriteRet, Required: false},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "bytes", Name: "bytes"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
			},
		},
		CgroupAttachTask: {
			id32Bit: sys32undefined,
			name:    "cgroup_attach_task",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.CgroupAttachTask, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "cgroup_path"},
				{Type: "const char*", Name: "comm"},
				{Type: "pid_t", Name: "pid"},
			},
		},
		CgroupMkdir: {
			id32Bit: sys32undefined,
			name:    "cgroup_mkdir",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.CgroupMkdir, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "u64", Name: "cgroup_id"},
				{Type: "const char*", Name: "cgroup_path"},
				{Type: "u32", Name: "hierarchy_id"},
			},
		},
		CgroupRmdir: {
			id32Bit: sys32undefined,
			name:    "cgroup_rmdir",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.CgroupRmdir, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "u64", Name: "cgroup_id"},
				{Type: "const char*", Name: "cgroup_path"},
				{Type: "u32", Name: "hierarchy_id"},
			},
		},
		SecurityBprmCheck: {
			id32Bit: sys32undefined,
			name:    "security_bprm_check",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityBPRMCheck, Required: true},
				},
			},
			sets: []string{"lsm_hooks", "proc", "proc_life"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
			},
		},
		SecurityFileOpen: {
			id32Bit: sys32undefined,
			name:    "security_file_open",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityFileOpen, Required: true},
					{Handle: probes.SyscallEnter__Internal, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{
							uint32(Open), uint32(Openat), uint32(Openat2),
							uint32(OpenByHandleAt), uint32(Execve),
							uint32(Execveat),
						},
					),
				},
			},
			sets: []string{"lsm_hooks", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "const char*", Name: "syscall_pathname"},
			},
		},
		SecurityInodeUnlink: {
			id32Bit: sys32undefined,
			name:    "security_inode_unlink",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityInodeUnlink, Required: true},
				},
			},
			sets: []string{"default", "lsm_hooks", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "dev_t", Name: "dev"},
				{Type: "u64", Name: "ctime"},
			},
		},
		SecuritySocketCreate: {
			id32Bit: sys32undefined,
			name:    "security_socket_create",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecuritySocketCreate, Required: true},
				},
			},
			sets: []string{"lsm_hooks", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "family"},
				{Type: "int", Name: "type"},
				{Type: "int", Name: "protocol"},
				{Type: "int", Name: "kern"},
			},
		},
		SecuritySocketListen: {
			id32Bit: sys32undefined,
			name:    "security_socket_listen",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecuritySocketListen, Required: true},
					{Handle: probes.SyscallEnter__Internal, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Listen)},
					),
				},
			},
			sets: []string{"lsm_hooks", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "local_addr"},
				{Type: "int", Name: "backlog"},
			},
		},
		SecuritySocketConnect: {
			id32Bit: sys32undefined,
			name:    "security_socket_connect",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecuritySocketConnect, Required: true},
					{Handle: probes.SyscallEnter__Internal, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Connect)},
					),
				},
			},
			sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "remote_addr"},
			},
		},
		SecuritySocketAccept: {
			id32Bit: sys32undefined,
			name:    "security_socket_accept",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecuritySocketAccept, Required: true},
					{Handle: probes.SyscallEnter__Internal, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Accept), uint32(Accept4)},
					),
				},
			},
			sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "local_addr"},
			},
		},
		SecuritySocketBind: {
			id32Bit: sys32undefined,
			name:    "security_socket_bind",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecuritySocketBind, Required: true},
					{Handle: probes.SyscallEnter__Internal, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Bind)},
					),
				},
			},
			sets: []string{"default", "lsm_hooks", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "local_addr"},
			},
		},
		SecuritySocketSetsockopt: {
			id32Bit: sys32undefined,
			name:    "security_socket_setsockopt",
			docPath: "lsm_hooks/security_socket_setsockopt.md",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecuritySocketSetsockopt, Required: true},
					{Handle: probes.SyscallEnter__Internal, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Setsockopt)},
					),
				},
			},
			sets: []string{"lsm_hooks", "net", "net_sock"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "int", Name: "level"},
				{Type: "int", Name: "optname"},
				{Type: "struct sockaddr*", Name: "local_addr"},
			},
		},
		SecuritySbMount: {
			id32Bit: sys32undefined,
			name:    "security_sb_mount",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecuritySbMount, Required: true},
				},
			},
			sets: []string{"default", "lsm_hooks", "fs"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "dev_name"},
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "type"},
				{Type: "unsigned long", Name: "flags"},
			},
		},
		SecurityBPF: {
			id32Bit: sys32undefined,
			name:    "security_bpf",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityBPF, Required: true},
				},
			},
			sets: []string{"lsm_hooks"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "cmd"},
			},
		},
		SecurityBPFMap: {
			id32Bit: sys32undefined,
			name:    "security_bpf_map",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityBPFMap, Required: true},
				},
			},
			sets: []string{"lsm_hooks"},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "map_id"},
				{Type: "const char*", Name: "map_name"},
			},
		},
		SecurityKernelReadFile: {
			id32Bit: sys32undefined,
			name:    "security_kernel_read_file",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityKernelReadFile, Required: true},
				},
			},
			sets: []string{"lsm_hooks"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "int", Name: "type"},
				{Type: "unsigned long", Name: "ctime"},
			},
		},
		SecurityPostReadFile: {
			id32Bit: sys32undefined,
			name:    "security_kernel_post_read_file",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityKernelPostReadFile, Required: true},
				},
			},
			sets: []string{"lsm_hooks"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "long", Name: "size"},
				{Type: "int", Name: "type"},
			},
		},
		SecurityInodeMknod: {
			id32Bit: sys32undefined,
			name:    "security_inode_mknod",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityInodeMknod, Required: true},
				},
			},
			sets: []string{"lsm_hooks"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "file_name"},
				{Type: "umode_t", Name: "mode"},
				{Type: "dev_t", Name: "dev"},
			},
		},
		SecurityInodeSymlinkEventId: {
			id32Bit: sys32undefined,
			name:    "security_inode_symlink",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityInodeSymlink, Required: true},
				},
			},
			sets: []string{"lsm_hooks", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "linkpath"},
				{Type: "const char*", Name: "target"},
			},
		},
		SecurityMmapFile: {
			id32Bit: sys32undefined,
			name:    "security_mmap_file",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityMmapFile, Required: true},
				},
			},
			sets: []string{"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "unsigned long", Name: "prot"},
				{Type: "unsigned long", Name: "mmap_flags"},
			},
		},
		DoMmap: {
			id32Bit: sys32undefined,
			name:    "do_mmap",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DoMmap, Required: true},
					{Handle: probes.DoMmapRet, Required: true},
				},
			},
			sets: []string{"fs", "fs_file_ops", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "void*", Name: "addr"},
				{Type: "const char*", Name: "pathname"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "unsigned long", Name: "pgoff"},
				{Type: "unsigned long", Name: "len"},
				{Type: "unsigned long", Name: "prot"},
				{Type: "unsigned long", Name: "mmap_flags"},
			},
		},
		SecurityFileMprotect: {
			id32Bit: sys32undefined,
			name:    "security_file_mprotect",
			docPath: "lsm_hooks/security_file_mprotect.md",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityFileMProtect, Required: true},
					{Handle: probes.SyscallEnter__Internal, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Mprotect), uint32(PkeyMprotect)},
					),
				},
			},
			sets: []string{"lsm_hooks", "proc", "proc_mem", "fs", "fs_file_ops"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "prot"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "int", Name: "prev_prot"},
				{Type: "void*", Name: "addr"},
				{Type: "size_t", Name: "len"},
				{Type: "int", Name: "pkey"},
			},
		},
		InitNamespaces: {
			id32Bit: sys32undefined,
			name:    "init_namespaces",
			sets:    []string{},
			dependencies: Dependencies{
				Capabilities: Capabilities{
					capabilities.Base: []cap.Value{
						cap.SYS_PTRACE,
					},
				},
			},
			params: []trace.ArgMeta{
				{Type: "u32", Name: "cgroup"},
				{Type: "u32", Name: "ipc"},
				{Type: "u32", Name: "mnt"},
				{Type: "u32", Name: "net"},
				{Type: "u32", Name: "pid"},
				{Type: "u32", Name: "pid_for_children"},
				{Type: "u32", Name: "time"},
				{Type: "u32", Name: "time_for_children"},
				{Type: "u32", Name: "user"},
				{Type: "u32", Name: "uts"},
			},
		},
		SocketDup: {
			id32Bit: sys32undefined,
			name:    "socket_dup",
			dependencies: Dependencies{
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Dup), uint32(Dup2), uint32(Dup3)},
					),
					NewTailCall(
						"sys_exit_init_tail",
						"sys_exit_init",
						[]uint32{uint32(Dup), uint32(Dup2), uint32(Dup3)},
					),
					NewTailCall(
						"sys_exit_tails",
						"sys_dup_exit_tail",
						[]uint32{uint32(Dup), uint32(Dup2), uint32(Dup3)},
					),
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "oldfd"},
				{Type: "int", Name: "newfd"},
				{Type: "struct sockaddr*", Name: "remote_addr"},
			},
		},
		HiddenInodes: {
			id32Bit: sys32undefined,
			name:    "hidden_inodes",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.Filldir64, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "char*", Name: "hidden_process"},
			},
		},
		KernelWrite: {
			id32Bit: sys32undefined,
			name:    "__kernel_write",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.KernelWrite, Required: true},
					{Handle: probes.KernelWriteRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "pos"},
			},
		},
		DirtyPipeSplice: {
			id32Bit: sys32undefined,
			name:    "dirty_pipe_splice",
			sets:    []string{},
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DoSplice, Required: true},
					{Handle: probes.DoSpliceRet, Required: true},
				},
				KSymbols: &[]KSymbol{
					{Symbol: "pipefifo_fops", Required: true},
				},
			},
			params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "inode_in"},
				{Type: "umode_t", Name: "in_file_type"},
				{Type: "const char*", Name: "in_file_path"},
				{Type: "loff_t", Name: "exposed_data_start_offset"},
				{Type: "size_t", Name: "exposed_data_len"},
				{Type: "unsigned long", Name: "inode_out"},
				{Type: "unsigned int", Name: "out_pipe_last_buffer_flags"},
			},
		},
		ContainerCreate: {
			id32Bit: sys32undefined,
			name:    "container_create",
			dependencies: Dependencies{
				Events: []ID{CgroupMkdir},
			},
			sets: []string{"default", "containers"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "runtime"},
				{Type: "const char*", Name: "container_id"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "const char*", Name: "container_image"},
				{Type: "const char*", Name: "container_image_digest"},
				{Type: "const char*", Name: "container_name"},
				{Type: "const char*", Name: "pod_name"},
				{Type: "const char*", Name: "pod_namespace"},
				{Type: "const char*", Name: "pod_uid"},
				{Type: "bool", Name: "pod_sandbox"},
			},
		},
		ContainerRemove: {
			id32Bit: sys32undefined,
			name:    "container_remove",
			dependencies: Dependencies{
				Events: []ID{CgroupRmdir},
			},
			sets: []string{"default", "containers"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "runtime"},
				{Type: "const char*", Name: "container_id"},
			},
		},
		ExistingContainer: {
			id32Bit: sys32undefined,
			name:    "existing_container",
			sets:    []string{"containers"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "runtime"},
				{Type: "const char*", Name: "container_id"},
				{Type: "unsigned long", Name: "ctime"},
				{Type: "const char*", Name: "container_image"},
				{Type: "const char*", Name: "container_image_digest"},
				{Type: "const char*", Name: "container_name"},
				{Type: "const char*", Name: "pod_name"},
				{Type: "const char*", Name: "pod_namespace"},
				{Type: "const char*", Name: "pod_uid"},
				{Type: "bool", Name: "pod_sandbox"},
			},
		},
		ProcCreate: {
			id32Bit: sys32undefined,
			name:    "proc_create",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.ProcCreate, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "char*", Name: "name"},
				{Type: "void*", Name: "proc_ops_addr"},
			},
		},
		KprobeAttach: {
			id32Bit: sys32undefined,
			name:    "kprobe_attach",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.RegisterKprobe, Required: true},
					{Handle: probes.RegisterKprobeRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "char*", Name: "symbol_name"},
				{Type: "void*", Name: "pre_handler_addr"},
				{Type: "void*", Name: "post_handler_addr"},
			},
		},
		CallUsermodeHelper: {
			id32Bit: sys32undefined,
			name:    "call_usermodehelper",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.CallUsermodeHelper, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "const char*const*", Name: "argv"},
				{Type: "const char*const*", Name: "envp"},
				{Type: "int", Name: "wait"},
			},
		},
		DebugfsCreateFile: {
			id32Bit: sys32undefined,
			name:    "debugfs_create_file",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DebugfsCreateFile, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "file_name"},
				{Type: "const char*", Name: "path"},
				{Type: "mode_t", Name: "mode"},
				{Type: "void*", Name: "proc_ops_addr"},
			},
		},
		PrintSyscallTable: {
			id32Bit:  sys32undefined,
			name:     "print_syscall_table",
			internal: true,
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.PrintSyscallTable, Required: true},
				},
				KSymbols: &[]KSymbol{
					{Symbol: "sys_call_table", Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "unsigned long[]", Name: "syscalls_addresses"},
				{Type: "unsigned long", Name: trigger.ContextArgName},
			},
		},
		HiddenKernelModule: {
			id32Bit: sys32undefined,
			name:    "hidden_kernel_module",
			dependencies: Dependencies{
				Events: []ID{
					HiddenKernelModuleSeeker,
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "address"},
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "srcversion"},
			},
		},
		HiddenKernelModuleSeeker: {
			id32Bit:  sys32undefined,
			name:     "hidden_kernel_module_seeker",
			internal: true,
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.HiddenKernelModuleSeeker, Required: true},
					{Handle: probes.HiddenKernelModuleVerifier, Required: true},
					{Handle: probes.ModuleLoad, Required: true},
					{Handle: probes.ModuleFree, Required: true},
					{Handle: probes.DoInitModule, Required: true},
					{Handle: probes.DoInitModuleRet, Required: true},
					{Handle: probes.LayoutAndAllocate, Required: true},
				},
				KSymbols: &[]KSymbol{
					{Symbol: "modules", Required: true},
					{Symbol: "module_kset", Required: true},
					{Symbol: "mod_tree", Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"prog_array",
						"lkm_seeker_proc_tail",
						[]uint32{TailHiddenKernelModuleProc},
					),
					NewTailCall(
						"prog_array",
						"lkm_seeker_kset_tail",
						[]uint32{TailHiddenKernelModuleKset},
					),
					NewTailCall(
						"prog_array",
						"lkm_seeker_mod_tree_tail",
						[]uint32{TailHiddenKernelModuleModTree},
					),
					NewTailCall(
						"prog_array",
						"lkm_seeker_new_mod_only_tail",
						[]uint32{TailHiddenKernelModuleNewModOnly},
					),
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "unsigned long", Name: "address"},
				{Type: "bytes", Name: "name"},
				{Type: "unsigned int", Name: "flags"},
				{Type: "bytes", Name: "srcversion"},
			},
		},
		HookedSyscalls: {
			id32Bit: sys32undefined,
			name:    "hooked_syscalls",
			dependencies: Dependencies{
				KSymbols: &[]KSymbol{
					{Symbol: "_stext", Required: true},
					{Symbol: "_etext", Required: true},
				},
				Events: []ID{
					DoInitModule,
					PrintSyscallTable,
				},
				Capabilities: Capabilities{
					capabilities.Base: []cap.Value{
						cap.SYSLOG, // read /proc/kallsyms
					},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "[]char*", Name: "check_syscalls"},
				{Type: "[]trace.HookedSymbolData", Name: "hooked_syscalls"},
			},
		},
		DebugfsCreateDir: {
			id32Bit: sys32undefined,
			name:    "debugfs_create_dir",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DebugfsCreateDir, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "path"},
			},
		},
		DeviceAdd: {
			id32Bit: sys32undefined,
			name:    "device_add",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DeviceAdd, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "parent_name"},
			},
		},
		RegisterChrdev: {
			id32Bit: sys32undefined,
			name:    "register_chrdev",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.RegisterChrdev, Required: true},
					{Handle: probes.RegisterChrdevRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "unsigned int", Name: "requested_major_number"},
				{Type: "unsigned int", Name: "granted_major_number"},
				{Type: "const char*", Name: "char_device_name"},
				{Type: "struct file_operations *", Name: "char_device_fops"},
			},
		},
		SharedObjectLoaded: {
			id32Bit: sys32undefined,
			name:    "shared_object_loaded",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityMmapFile, Required: true},
				},
				Capabilities: Capabilities{
					capabilities.Base: []cap.Value{
						cap.SYS_PTRACE, // loadSharedObjectDynamicSymbols()
					},
				},
			},
			sets: []string{"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "ctime"},
			},
		},
		SymbolsLoaded: {
			id32Bit: sys32undefined,
			name:    "symbols_loaded",
			docPath: "security_alerts/symbols_load.md",
			dependencies: Dependencies{
				Events: []ID{
					SharedObjectLoaded,
					SchedProcessExec, // Used to get mount namespace cache
				},
			},
			sets: []string{"derived", "fs", "security_alert"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "library_path"},
				{Type: "const char*const*", Name: "symbols"},
			},
		},
		SymbolsCollision: {
			id32Bit: sys32undefined,
			name:    "symbols_collision",
			docPath: "security_alerts/symbols_collision.md",
			dependencies: Dependencies{
				Events: []ID{
					SharedObjectLoaded,
					SchedProcessExec, // Used to get mount namespace cache
				},
			},
			sets: []string{"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "loaded_path"},
				{Type: "const char*", Name: "collision_path"},
				{Type: "const char*const*", Name: "symbols"},
			},
		},
		CaptureFileWrite: {
			id32Bit:  sys32undefined,
			name:     "capture_file_write",
			internal: true,
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.VfsWrite, Required: true},
					{Handle: probes.VfsWriteRet, Required: true},
					{Handle: probes.VfsWriteV, Required: false},
					{Handle: probes.VfsWriteVRet, Required: false},
					{Handle: probes.KernelWrite, Required: false},
					{Handle: probes.KernelWriteRet, Required: false},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"prog_array",
						"trace_ret_vfs_write_tail",
						[]uint32{TailVfsWrite},
					),
					NewTailCall(
						"prog_array",
						"trace_ret_vfs_writev_tail",
						[]uint32{TailVfsWritev},
					),
					NewTailCall(
						"prog_array",
						"trace_ret_kernel_write_tail",
						[]uint32{TailKernelWrite},
					),
					NewTailCall(
						"prog_array",
						"send_bin",
						[]uint32{TailSendBin},
					),
				},
				KSymbols: &[]KSymbol{
					{Symbol: "pipefifo_fops", Required: true},
				},
			},
		},
		CaptureFileRead: {
			id32Bit:  sys32undefined,
			name:     "capture_file_read",
			internal: true,
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.VfsRead, Required: true},
					{Handle: probes.VfsReadRet, Required: true},
					{Handle: probes.VfsReadV, Required: false},
					{Handle: probes.VfsReadVRet, Required: false},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"prog_array",
						"trace_ret_vfs_read_tail",
						[]uint32{TailVfsRead},
					),
					NewTailCall(
						"prog_array",
						"trace_ret_vfs_readv_tail",
						[]uint32{TailVfsReadv},
					),
					NewTailCall(
						"prog_array",
						"send_bin",
						[]uint32{TailSendBin},
					),
				},
				KSymbols: &[]KSymbol{
					{Symbol: "pipefifo_fops", Required: true},
				},
			},
		},
		CaptureExec: {
			id32Bit:  sys32undefined,
			name:     "capture_exec",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					SchedProcessExec,
				},
				Capabilities: Capabilities{
					capabilities.Base: []cap.Value{
						cap.SYS_PTRACE, // processSchedProcessExec() performance
					},
				},
			},
		},
		CaptureModule: {
			id32Bit:  sys32undefined,
			name:     "capture_module",
			internal: true,
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SyscallEnter__Internal, Required: true},
					{Handle: probes.SyscallExit__Internal, Required: true},
					{Handle: probes.SecurityKernelPostReadFile, Required: true},
				},
				Events: []ID{
					SchedProcessExec,
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_tails",
						"syscall__init_module",
						[]uint32{uint32(InitModule)},
					),
					NewTailCall(
						"prog_array_tp",
						"send_bin_tp",
						[]uint32{TailSendBinTP},
					),
					NewTailCall(
						"prog_array",
						"send_bin",
						[]uint32{TailSendBin},
					),
				},
			},
		},
		CaptureMem: {
			id32Bit:  sys32undefined,
			name:     "capture_mem",
			internal: true,
			dependencies: Dependencies{
				TailCalls: []*TailCall{
					NewTailCall(
						"prog_array",
						"send_bin",
						[]uint32{TailSendBin},
					),
				},
			},
		},
		CaptureBpf: {
			id32Bit:  sys32undefined,
			name:     "capture_bpf",
			internal: true,
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityBPF, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"prog_array",
						"send_bin",
						[]uint32{TailSendBin},
					),
				},
			},
		},
		DoInitModule: {
			id32Bit: sys32undefined,
			name:    "do_init_module",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DoInitModule, Required: true},
					{Handle: probes.DoInitModuleRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "version"},
				{Type: "const char*", Name: "src_version"},
			},
		},
		ModuleLoad: {
			id32Bit: sys32undefined,
			name:    "module_load",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.ModuleLoad, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "version"},
				{Type: "const char*", Name: "src_version"},
			},
		},
		ModuleFree: {
			id32Bit: sys32undefined,
			name:    "module_free",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.ModuleFree, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "name"},
				{Type: "const char*", Name: "version"},
				{Type: "const char*", Name: "src_version"},
			},
		},
		SocketAccept: {
			id32Bit:  sys32undefined,
			name:     "socket_accept",
			internal: false,
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SyscallEnter__Internal, Required: true},
					{Handle: probes.SyscallExit__Internal, Required: true},
				},
				Events: []ID{
					SecuritySocketAccept,
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_exit_tails",
						"syscall__accept4",
						[]uint32{uint32(Accept), uint32(Accept4)},
					),
					NewTailCall(
						"sys_exit_init_tail",
						"sys_exit_init",
						[]uint32{uint32(Accept), uint32(Accept4)},
					),
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sockfd"},
				{Type: "struct sockaddr*", Name: "local_addr"},
				{Type: "struct sockaddr*", Name: "remote_addr"}},
		},
		LoadElfPhdrs: {
			id32Bit: sys32undefined,
			name:    "load_elf_phdrs",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.LoadElfPhdrs, Required: true},
				},
			},
			sets: []string{"proc"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
			},
		},
		HookedProcFops: {
			id32Bit: sys32undefined,
			name:    "hooked_proc_fops",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityFilePermission, Required: true},
				},
				KSymbols: &[]KSymbol{
					{Symbol: "_stext", Required: true},
					{Symbol: "_etext", Required: true},
				},
				Events: []ID{
					DoInitModule,
				},
				Capabilities: Capabilities{
					capabilities.Base: []cap.Value{
						cap.SYSLOG, // read /proc/kallsyms
					},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "[]trace.HookedSymbolData", Name: "hooked_fops_pointers"},
			},
		},
		PrintNetSeqOps: {
			id32Bit: sys32undefined,
			name:    "print_net_seq_ops",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.PrintNetSeqOps, Required: true},
				},
				KSymbols: &[]KSymbol{
					{Symbol: "tcp4_seq_ops", Required: true},
					{Symbol: "tcp6_seq_ops", Required: true},
					{Symbol: "udp_seq_ops", Required: true},
					{Symbol: "udp6_seq_ops", Required: true},
					{Symbol: "raw_seq_ops", Required: true},
					{Symbol: "raw6_seq_ops", Required: true},
				},
			},
			internal: true,
			sets:     []string{},
			params: []trace.ArgMeta{
				{Type: "unsigned long[]", Name: "net_seq_ops"},
				{Type: "unsigned long", Name: trigger.ContextArgName},
			},
		},
		HookedSeqOps: {
			id32Bit: sys32undefined,
			name:    "hooked_seq_ops",
			dependencies: Dependencies{
				KSymbols: &[]KSymbol{
					{Symbol: "_stext", Required: true},
					{Symbol: "_etext", Required: true},
				},
				Events: []ID{
					PrintNetSeqOps,
					DoInitModule,
				},
				Capabilities: Capabilities{
					capabilities.Base: []cap.Value{
						cap.SYSLOG, // read /proc/kallsyms
					},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "map[string]trace.HookedSymbolData", Name: "hooked_seq_ops"},
			},
		},
		TaskRename: {
			id32Bit: sys32undefined,
			name:    "task_rename",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.TaskRename, Required: true},
				},
			},
			sets: []string{"proc"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "old_name"},
				{Type: "const char*", Name: "new_name"},
			},
		},
		SecurityInodeRename: {
			id32Bit: sys32undefined,
			name:    "security_inode_rename",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityInodeRename, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "old_path"},
				{Type: "const char*", Name: "new_path"},
			},
		},
		DoSigaction: {
			id32Bit: sys32undefined,
			name:    "do_sigaction",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DoSigaction, Required: true},
				},
			},
			sets: []string{"proc"},
			params: []trace.ArgMeta{
				{Type: "int", Name: "sig"},
				{Type: "bool", Name: "is_sa_initialized"},
				{Type: "unsigned long", Name: "sa_flags"},
				{Type: "unsigned long", Name: "sa_mask"},
				{Type: "u8", Name: "sa_handle_method"},
				{Type: "void*", Name: "sa_handler"},
				{Type: "bool", Name: "is_old_sa_initialized"},
				{Type: "unsigned long", Name: "old_sa_flags"},
				{Type: "unsigned long", Name: "old_sa_mask"},
				{Type: "u8", Name: "old_sa_handle_method"},
				{Type: "void*", Name: "old_sa_handler"},
			},
		},
		BpfAttach: {
			id32Bit: sys32undefined,
			name:    "bpf_attach",
			docPath: "docs/events/builtin/extra/bpf_attach.md",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityFileIoctl, Required: true},
					{Handle: probes.SecurityBpfProg, Required: true},
					{Handle: probes.SecurityBPF, Required: true},
					{Handle: probes.TpProbeRegPrioMayExist, Required: true},
					{Handle: probes.CheckHelperCall, Required: false},
					{Handle: probes.CheckMapFuncCompatibility, Required: false},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "prog_type"},
				{Type: "const char*", Name: "prog_name"},
				{Type: "u32", Name: "prog_id"},
				{Type: "unsigned long[]", Name: "prog_helpers"},
				{Type: "const char*", Name: "symbol_name"},
				{Type: "u64", Name: "symbol_addr"},
				{Type: "int", Name: "attach_type"},
			},
		},
		KallsymsLookupName: {
			id32Bit: sys32undefined,
			name:    "kallsyms_lookup_name",
			docPath: "kprobes/kallsyms_lookup_name.md",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.KallsymsLookupName, Required: true},
					{Handle: probes.KallsymsLookupNameRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "symbol_name"},
				{Type: "void*", Name: "symbol_address"},
			},
		},
		PrintMemDump: {
			id32Bit: sys32undefined,
			name:    "print_mem_dump",
			sets:    []string{},
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.PrintMemDump, Required: true},
				},
				Events: []ID{
					DoInitModule,
				},
				KSymbols: &[]KSymbol{},
				Capabilities: Capabilities{
					capabilities.Base: []cap.Value{
						cap.SYSLOG, // read /proc/kallsyms
					},
				},
			},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "bytes"},
				{Type: "void*", Name: "address"},
				{Type: "u64", Name: "length"},
				{Type: "u64", Name: "caller_context_id"},
				{Type: "char*", Name: "arch"},
				{Type: "char*", Name: "symbol_name"},
				{Type: "char*", Name: "symbol_owner"},
			},
		},
		VfsRead: {
			id32Bit: sys32undefined,
			name:    "vfs_read",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.VfsRead, Required: true},
					{Handle: probes.VfsReadRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "size_t", Name: "count"},
				{Type: "off_t", Name: "pos"},
			},
		},
		VfsReadv: {
			id32Bit: sys32undefined,
			name:    "vfs_readv",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.VfsReadV, Required: true},
					{Handle: probes.VfsReadVRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "vlen"},
				{Type: "off_t", Name: "pos"},
			},
		},
		VfsUtimes: {
			id32Bit: sys32undefined,
			name:    "vfs_utimes",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.VfsUtimes, Required: false},    // this probe exits in kernels >= 5.9
					{Handle: probes.UtimesCommon, Required: false}, // this probe exits in kernels < 5.9
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "u64", Name: "atime"},
				{Type: "u64", Name: "mtime"},
			},
		},
		DoTruncate: {
			id32Bit: sys32undefined,
			name:    "do_truncate",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.DoTruncate, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "dev_t", Name: "dev"},
				{Type: "u64", Name: "length"},
			},
		},
		FileModification: {
			id32Bit: sys32undefined,
			name:    "file_modification",
			docPath: "kprobes/file_modification.md",
			sets:    []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "file_path"},
				{Type: "dev_t", Name: "dev"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "unsigned long", Name: "old_ctime"},
				{Type: "unsigned long", Name: "new_ctime"},
			},
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.FdInstall, Required: true},
					{Handle: probes.FilpClose, Required: true},
					{Handle: probes.FileUpdateTime, Required: true},
					{Handle: probes.FileUpdateTimeRet, Required: true},
					{Handle: probes.FileModified, Required: false},    // not required because doesn't ...
					{Handle: probes.FileModifiedRet, Required: false}, // ... exist in kernels < 5.3
				},
			},
		},
		InotifyWatch: {
			id32Bit: sys32undefined,
			name:    "inotify_watch",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.InotifyFindInode, Required: true},
					{Handle: probes.InotifyFindInodeRet, Required: true},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "unsigned long", Name: "inode"},
				{Type: "dev_t", Name: "dev"},
			},
		},
		SecurityBpfProg: {
			id32Bit: sys32undefined,
			name:    "security_bpf_prog",
			docPath: "docs/events/builtin/extra/security_bpf_prog.md",
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.SecurityBpfProg, Required: true},
					{Handle: probes.BpfCheck, Required: true},
					{Handle: probes.CheckHelperCall, Required: false},
					{Handle: probes.CheckMapFuncCompatibility, Required: false},
				},
			},
			sets: []string{},
			params: []trace.ArgMeta{
				{Type: "int", Name: "type"},
				{Type: "const char*", Name: "name"},
				{Type: "unsigned long[]", Name: "helpers"},
				{Type: "u32", Name: "id"},
				{Type: "bool", Name: "load"},
			},
		},
		ProcessExecuteFailed: {
			id32Bit: sys32undefined,
			name:    "process_execute_failed",
			sets:    []string{"proc"},
			dependencies: Dependencies{
				Probes: []Probe{
					{Handle: probes.ExecBinprm, Required: true},
					{Handle: probes.ExecBinprmRet, Required: true},
				},
				TailCalls: []*TailCall{
					NewTailCall(
						"sys_enter_init_tail",
						"sys_enter_init",
						[]uint32{uint32(Execve), uint32(Execveat)},
					),
					NewTailCall(
						"prog_array",
						"trace_ret_exec_binprm1",
						[]uint32{TailExecBinprm1},
					),
					NewTailCall(
						"prog_array",
						"trace_ret_exec_binprm2",
						[]uint32{TailExecBinprm2},
					),
				},
			},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "path"},
				{Type: "const char*", Name: "binary.path"},
				{Type: "dev_t", Name: "binary.device_id"},
				{Type: "unsigned long", Name: "binary.inode_number"},
				{Type: "unsigned long", Name: "binary.ctime"},
				{Type: "umode_t", Name: "binary.inode_mode"},
				{Type: "const char*", Name: "interpreter_path"},
				{Type: "umode_t", Name: "stdin_type"},
				{Type: "char*", Name: "stdin_path"},
				{Type: "int", Name: "kernel_invoked"},
				{Type: "const char*const*", Name: "binary.arguments"},
				{Type: "const char*const*", Name: "environment"},
			},
		},
		//
		// Network Protocol Event Types (add new events above here)
		//
		NetPacketBase: {
			id32Bit:  sys32undefined,
			name:     "net_packet_base",
			internal: true,
			dependencies: Dependencies{
				Capabilities: Capabilities{
					capabilities.EBPF: []cap.Value{
						cap.NET_ADMIN, // needed for BPF_PROG_TYPE_CGROUP_SKB
					},
				},
				Probes: []Probe{
					{Handle: probes.CgroupSKBIngress, Required: true},
					{Handle: probes.CgroupSKBEgress, Required: true},
					{Handle: probes.SockAllocFile, Required: true},
					{Handle: probes.SockAllocFileRet, Required: true},
					{Handle: probes.CgroupBPFRunFilterSKB, Required: true},
					{Handle: probes.SecuritySocketRecvmsg, Required: true},
					{Handle: probes.SecuritySocketSendmsg, Required: true},
					{Handle: probes.SecuritySkClone, Required: true},
				},
			},
			sets:   []string{"network_events"},
			params: []trace.ArgMeta{},
		},
		NetPacketIPBase: {
			id32Bit:  sys32undefined,
			name:     "net_packet_ip_base",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					NetPacketBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "payload"},
			},
		},
		NetPacketIPv4: {
			id32Bit: sys32undefined,
			name:    "net_packet_ipv4",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketIPBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "src"}, // TODO: remove after filter supports ProtoIPv4
				{Type: "const char*", Name: "dst"}, // TODO: remove after filter supports ProtoIPv4
				{Type: "trace.ProtoIPv4", Name: "proto_ipv4"},
			},
		},
		NetPacketIPv6: {
			id32Bit: sys32undefined,
			name:    "net_packet_ipv6",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketIPBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "src"}, // TODO: remove after filter supports ProtoIPv6
				{Type: "const char*", Name: "dst"}, // TODO: remove after filter supports ProtoIPv6
				{Type: "trace.ProtoIPv6", Name: "proto_ipv6"},
			},
		},
		NetPacketTCPBase: {
			id32Bit:  sys32undefined,
			name:     "net_packet_tcp_base",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					NetPacketBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "payload"},
			},
		},
		NetPacketTCP: {
			id32Bit: sys32undefined,
			name:    "net_packet_tcp",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketTCPBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "src"},
				{Type: "const char*", Name: "dst"},
				{Type: "u16", Name: "src_port"}, // TODO: remove after filter supports ProtoTCP
				{Type: "u16", Name: "dst_port"}, // TODO: remove after filter supports ProtoTCP
				{Type: "trace.ProtoTCP", Name: "proto_tcp"},
			},
		},
		NetPacketUDPBase: {
			id32Bit:  sys32undefined,
			name:     "net_packet_udp_base",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					NetPacketBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "payload"},
			},
		},
		NetPacketUDP: {
			id32Bit: sys32undefined,
			name:    "net_packet_udp",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketUDPBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "src"},
				{Type: "const char*", Name: "dst"},
				{Type: "u16", Name: "src_port"}, // TODO: remove after filter supports ProtoUDP
				{Type: "u16", Name: "dst_port"}, // TODO: remove after filter supports ProtoUDP
				{Type: "trace.ProtoUDP", Name: "proto_udp"},
			},
		},
		NetPacketICMPBase: {
			id32Bit: sys32undefined,
			name:    "net_packet_icmp_base",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketBase,
				},
			},
			internal: true,
			sets:     []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "payload"},
			},
		},
		NetPacketICMP: {
			id32Bit: sys32undefined,
			name:    "net_packet_icmp",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketICMPBase,
				},
			},
			sets: []string{"default", "network_events"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "src"},
				{Type: "const char*", Name: "dst"},
				{Type: "trace.ProtoICMP", Name: "proto_icmp"},
			},
		},
		NetPacketICMPv6Base: {
			id32Bit:  sys32undefined,
			name:     "net_packet_icmpv6_base",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					NetPacketBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "payload"},
			},
		},
		NetPacketICMPv6: {
			id32Bit: sys32undefined,
			name:    "net_packet_icmpv6",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketICMPv6Base,
				},
			},
			sets: []string{"default", "network_events"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "src"},
				{Type: "const char*", Name: "dst"},
				{Type: "trace.ProtoICMPv6", Name: "proto_icmpv6"},
			},
		},
		NetPacketDNSBase: {
			id32Bit:  sys32undefined,
			name:     "net_packet_dns_base",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					NetPacketBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "payload"},
			},
		},
		NetPacketDNS: {
			id32Bit: sys32undefined,
			name:    "net_packet_dns", // preferred event to write signatures
			dependencies: Dependencies{
				Events: []ID{
					NetPacketDNSBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "src"},
				{Type: "const char*", Name: "dst"},
				{Type: "u16", Name: "src_port"},
				{Type: "u16", Name: "dst_port"},
				{Type: "trace.ProtoDNS", Name: "proto_dns"},
			},
		},
		NetPacketDNSRequest: {
			id32Bit: sys32undefined,
			name:    "net_packet_dns_request", // simple dns event compatible dns_request (deprecated)
			dependencies: Dependencies{
				Events: []ID{
					NetPacketDNSBase,
				},
			},
			sets: []string{"default", "network_events"},
			params: []trace.ArgMeta{
				{Type: "trace.PktMeta", Name: "metadata"},
				{Type: "[]trace.DnsQueryData", Name: "dns_questions"},
			},
		},
		NetPacketDNSResponse: {
			id32Bit: sys32undefined,
			name:    "net_packet_dns_response", // simple dns event compatible dns_response (deprecated)
			dependencies: Dependencies{
				Events: []ID{
					NetPacketDNSBase,
				},
			},
			sets: []string{"default", "network_events"},
			params: []trace.ArgMeta{
				{Type: "trace.PktMeta", Name: "metadata"},
				{Type: "[]trace.DnsResponseData", Name: "dns_response"},
			},
		},
		NetPacketHTTPBase: {
			id32Bit:  sys32undefined,
			name:     "net_packet_http_base",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					NetPacketBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "payload"},
			},
		},
		NetPacketHTTP: {
			id32Bit: sys32undefined,
			name:    "net_packet_http", // preferred event to write signatures
			dependencies: Dependencies{
				Events: []ID{
					NetPacketHTTPBase,
				},
			},
			sets: []string{"network_events"},
			params: []trace.ArgMeta{
				{Type: "const char*", Name: "src"},
				{Type: "const char*", Name: "dst"},
				{Type: "u16", Name: "src_port"},
				{Type: "u16", Name: "dst_port"},
				{Type: "trace.ProtoHTTP", Name: "proto_http"},
			},
		},
		NetPacketHTTPRequest: {
			id32Bit: sys32undefined,
			name:    "net_packet_http_request",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketHTTPBase,
				},
			},
			sets: []string{"default", "network_events"},
			params: []trace.ArgMeta{
				{Type: "trace.PktMeta", Name: "metadata"},
				{Type: "trace.ProtoHTTPRequest", Name: "http_request"},
			},
		},
		NetPacketHTTPResponse: {
			id32Bit: sys32undefined,
			name:    "net_packet_http_response",
			dependencies: Dependencies{
				Events: []ID{
					NetPacketHTTPBase,
				},
			},
			sets: []string{"default", "network_events"},
			params: []trace.ArgMeta{
				{Type: "trace.PktMeta", Name: "metadata"},
				{Type: "trace.ProtoHTTPResponse", Name: "http_response"},
			},
		},
		NetPacketCapture: { // all packets have full payload (sent in a dedicated perfbuffer)
			id32Bit:  sys32undefined,
			name:     "net_packet_capture",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					NetPacketBase,
				},
			},
			params: []trace.ArgMeta{
				{Type: "bytes", Name: "payload"},
			},
		},
		CaptureNetPacket: { // network packet capture pseudo event
			id32Bit:  sys32undefined,
			name:     "capture_net_packet",
			internal: true,
			dependencies: Dependencies{
				Events: []ID{
					NetPacketCapture,
				},
			},
		},
		// NOTE: add new events before the network events (keep them at the end)
	},
}
