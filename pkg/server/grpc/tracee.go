package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/mennanov/fmutils"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/pkg/version"
	"github.com/aquasecurity/tracee/types/trace"
)

// EventTranslationTable translates internal to external protobuf Event Id
var EventTranslationTable = [events.MaxBuiltinID]pb.EventId{
	// syscall translation section
	events.Read:                  pb.EventId_read,
	events.Write:                 pb.EventId_write,
	events.Open:                  pb.EventId_open,
	events.Close:                 pb.EventId_close,
	events.Stat:                  pb.EventId_stat,
	events.Fstat:                 pb.EventId_fstat,
	events.Lstat:                 pb.EventId_lstat,
	events.Poll:                  pb.EventId_poll,
	events.Lseek:                 pb.EventId_lseek,
	events.Mmap:                  pb.EventId_mmap,
	events.Mprotect:              pb.EventId_mprotect,
	events.Munmap:                pb.EventId_munmap,
	events.Brk:                   pb.EventId_brk,
	events.RtSigaction:           pb.EventId_rt_sigaction,
	events.RtSigprocmask:         pb.EventId_rt_sigprocmask,
	events.RtSigreturn:           pb.EventId_rt_sigreturn,
	events.Ioctl:                 pb.EventId_ioctl,
	events.Pread64:               pb.EventId_pread64,
	events.Pwrite64:              pb.EventId_pwrite64,
	events.Readv:                 pb.EventId_readv,
	events.Writev:                pb.EventId_writev,
	events.Access:                pb.EventId_access,
	events.Pipe:                  pb.EventId_pipe,
	events.Select:                pb.EventId_select,
	events.SchedYield:            pb.EventId_sched_yield,
	events.Mremap:                pb.EventId_mremap,
	events.Msync:                 pb.EventId_msync,
	events.Mincore:               pb.EventId_mincore,
	events.Madvise:               pb.EventId_madvise,
	events.Shmget:                pb.EventId_shmget,
	events.Shmat:                 pb.EventId_shmat,
	events.Shmctl:                pb.EventId_shmctl,
	events.Dup:                   pb.EventId_dup,
	events.Dup2:                  pb.EventId_dup2,
	events.Pause:                 pb.EventId_pause,
	events.Nanosleep:             pb.EventId_nanosleep,
	events.Getitimer:             pb.EventId_getitimer,
	events.Alarm:                 pb.EventId_alarm,
	events.Setitimer:             pb.EventId_setitimer,
	events.Getpid:                pb.EventId_getpid,
	events.Sendfile:              pb.EventId_sendfile,
	events.Socket:                pb.EventId_socket,
	events.Connect:               pb.EventId_connect,
	events.Accept:                pb.EventId_accept,
	events.Sendto:                pb.EventId_sendto,
	events.Recvfrom:              pb.EventId_recvfrom,
	events.Sendmsg:               pb.EventId_sendmsg,
	events.Recvmsg:               pb.EventId_recvmsg,
	events.Shutdown:              pb.EventId_shutdown,
	events.Bind:                  pb.EventId_bind,
	events.Listen:                pb.EventId_listen,
	events.Getsockname:           pb.EventId_getsockname,
	events.Getpeername:           pb.EventId_getpeername,
	events.Socketpair:            pb.EventId_socketpair,
	events.Setsockopt:            pb.EventId_setsockopt,
	events.Getsockopt:            pb.EventId_getsockopt,
	events.Clone:                 pb.EventId_clone,
	events.Fork:                  pb.EventId_fork,
	events.Vfork:                 pb.EventId_vfork,
	events.Execve:                pb.EventId_execve,
	events.Exit:                  pb.EventId_exit,
	events.Wait4:                 pb.EventId_wait4,
	events.Kill:                  pb.EventId_kill,
	events.Uname:                 pb.EventId_uname,
	events.Semget:                pb.EventId_semget,
	events.Semop:                 pb.EventId_semop,
	events.Semctl:                pb.EventId_semctl,
	events.Shmdt:                 pb.EventId_shmdt,
	events.Msgget:                pb.EventId_msgget,
	events.Msgsnd:                pb.EventId_msgsnd,
	events.Msgrcv:                pb.EventId_msgrcv,
	events.Msgctl:                pb.EventId_msgctl,
	events.Fcntl:                 pb.EventId_fcntl,
	events.Flock:                 pb.EventId_flock,
	events.Fsync:                 pb.EventId_fsync,
	events.Fdatasync:             pb.EventId_fdatasync,
	events.Truncate:              pb.EventId_truncate,
	events.Ftruncate:             pb.EventId_ftruncate,
	events.Getdents:              pb.EventId_getdents,
	events.Getcwd:                pb.EventId_getcwd,
	events.Chdir:                 pb.EventId_chdir,
	events.Fchdir:                pb.EventId_fchdir,
	events.Rename:                pb.EventId_rename,
	events.Mkdir:                 pb.EventId_mkdir,
	events.Rmdir:                 pb.EventId_rmdir,
	events.Creat:                 pb.EventId_creat,
	events.Link:                  pb.EventId_link,
	events.Unlink:                pb.EventId_unlink,
	events.Symlink:               pb.EventId_symlink,
	events.Readlink:              pb.EventId_readlink,
	events.Chmod:                 pb.EventId_chmod,
	events.Fchmod:                pb.EventId_fchmod,
	events.Chown:                 pb.EventId_chown,
	events.Fchown:                pb.EventId_fchown,
	events.Lchown:                pb.EventId_lchown,
	events.Umask:                 pb.EventId_umask,
	events.Gettimeofday:          pb.EventId_gettimeofday,
	events.Getrlimit:             pb.EventId_getrlimit,
	events.Getrusage:             pb.EventId_getrusage,
	events.Sysinfo:               pb.EventId_sysinfo,
	events.Times:                 pb.EventId_times,
	events.Ptrace:                pb.EventId_ptrace,
	events.Getuid:                pb.EventId_getuid,
	events.Syslog:                pb.EventId_syslog,
	events.Getgid:                pb.EventId_getgid,
	events.Setuid:                pb.EventId_setuid,
	events.Setgid:                pb.EventId_setgid,
	events.Geteuid:               pb.EventId_geteuid,
	events.Getegid:               pb.EventId_getegid,
	events.Setpgid:               pb.EventId_setpgid,
	events.Getppid:               pb.EventId_getppid,
	events.Getpgrp:               pb.EventId_getpgrp,
	events.Setsid:                pb.EventId_setsid,
	events.Setreuid:              pb.EventId_setreuid,
	events.Setregid:              pb.EventId_setregid,
	events.Getgroups:             pb.EventId_getgroups,
	events.Setgroups:             pb.EventId_setgroups,
	events.Setresuid:             pb.EventId_setresuid,
	events.Getresuid:             pb.EventId_getresuid,
	events.Setresgid:             pb.EventId_setresgid,
	events.Getresgid:             pb.EventId_getresgid,
	events.Getpgid:               pb.EventId_getpgid,
	events.Setfsuid:              pb.EventId_setfsuid,
	events.Setfsgid:              pb.EventId_setfsgid,
	events.Getsid:                pb.EventId_getsid,
	events.Capget:                pb.EventId_capget,
	events.Capset:                pb.EventId_capset,
	events.RtSigpending:          pb.EventId_rt_sigpending,
	events.RtSigtimedwait:        pb.EventId_rt_sigtimedwait,
	events.RtSigqueueinfo:        pb.EventId_rt_sigqueueinfo,
	events.RtSigsuspend:          pb.EventId_rt_sigsuspend,
	events.Sigaltstack:           pb.EventId_sigaltstack,
	events.Utime:                 pb.EventId_utime,
	events.Mknod:                 pb.EventId_mknod,
	events.Uselib:                pb.EventId_uselib,
	events.Personality:           pb.EventId_personality,
	events.Ustat:                 pb.EventId_ustat,
	events.Statfs:                pb.EventId_statfs,
	events.Fstatfs:               pb.EventId_fstatfs,
	events.Sysfs:                 pb.EventId_sysfs,
	events.Getpriority:           pb.EventId_getpriority,
	events.Setpriority:           pb.EventId_setpriority,
	events.SchedSetparam:         pb.EventId_sched_setparam,
	events.SchedGetparam:         pb.EventId_sched_getparam,
	events.SchedSetscheduler:     pb.EventId_sched_setscheduler,
	events.SchedGetscheduler:     pb.EventId_sched_getscheduler,
	events.SchedGetPriorityMax:   pb.EventId_sched_get_priority_max,
	events.SchedGetPriorityMin:   pb.EventId_sched_get_priority_min,
	events.SchedRrGetInterval:    pb.EventId_sched_rr_get_interval,
	events.Mlock:                 pb.EventId_mlock,
	events.Munlock:               pb.EventId_munlock,
	events.Mlockall:              pb.EventId_mlockall,
	events.Munlockall:            pb.EventId_munlockall,
	events.Vhangup:               pb.EventId_vhangup,
	events.ModifyLdt:             pb.EventId_modify_ldt,
	events.PivotRoot:             pb.EventId_pivot_root,
	events.Sysctl:                pb.EventId_sysctl,
	events.Prctl:                 pb.EventId_prctl,
	events.ArchPrctl:             pb.EventId_arch_prctl,
	events.Adjtimex:              pb.EventId_adjtimex,
	events.Setrlimit:             pb.EventId_setrlimit,
	events.Chroot:                pb.EventId_chroot,
	events.Sync:                  pb.EventId_sync,
	events.Acct:                  pb.EventId_acct,
	events.Settimeofday:          pb.EventId_settimeofday,
	events.Mount:                 pb.EventId_mount,
	events.Umount2:               pb.EventId_umount2,
	events.Swapon:                pb.EventId_swapon,
	events.Swapoff:               pb.EventId_swapoff,
	events.Reboot:                pb.EventId_reboot,
	events.Sethostname:           pb.EventId_sethostname,
	events.Setdomainname:         pb.EventId_setdomainname,
	events.Iopl:                  pb.EventId_iopl,
	events.Ioperm:                pb.EventId_ioperm,
	events.CreateModule:          pb.EventId_create_module,
	events.InitModule:            pb.EventId_init_module,
	events.DeleteModule:          pb.EventId_delete_module,
	events.GetKernelSyms:         pb.EventId_get_kernel_syms,
	events.QueryModule:           pb.EventId_query_module,
	events.Quotactl:              pb.EventId_quotactl,
	events.Nfsservctl:            pb.EventId_nfsservctl,
	events.Getpmsg:               pb.EventId_getpmsg,
	events.Putpmsg:               pb.EventId_putpmsg,
	events.Afs:                   pb.EventId_afs,
	events.Tuxcall:               pb.EventId_tuxcall,
	events.Security:              pb.EventId_security,
	events.Gettid:                pb.EventId_gettid,
	events.Readahead:             pb.EventId_readahead,
	events.Setxattr:              pb.EventId_setxattr,
	events.Lsetxattr:             pb.EventId_lsetxattr,
	events.Fsetxattr:             pb.EventId_fsetxattr,
	events.Getxattr:              pb.EventId_getxattr,
	events.Lgetxattr:             pb.EventId_lgetxattr,
	events.Fgetxattr:             pb.EventId_fgetxattr,
	events.Listxattr:             pb.EventId_listxattr,
	events.Llistxattr:            pb.EventId_llistxattr,
	events.Flistxattr:            pb.EventId_flistxattr,
	events.Removexattr:           pb.EventId_removexattr,
	events.Lremovexattr:          pb.EventId_lremovexattr,
	events.Fremovexattr:          pb.EventId_fremovexattr,
	events.Tkill:                 pb.EventId_tkill,
	events.Time:                  pb.EventId_time,
	events.Futex:                 pb.EventId_futex,
	events.SchedSetaffinity:      pb.EventId_sched_setaffinity,
	events.SchedGetaffinity:      pb.EventId_sched_getaffinity,
	events.SetThreadArea:         pb.EventId_set_thread_area,
	events.IoSetup:               pb.EventId_io_setup,
	events.IoDestroy:             pb.EventId_io_destroy,
	events.IoGetevents:           pb.EventId_io_getevents,
	events.IoSubmit:              pb.EventId_io_submit,
	events.IoCancel:              pb.EventId_io_cancel,
	events.GetThreadArea:         pb.EventId_get_thread_area,
	events.LookupDcookie:         pb.EventId_lookup_dcookie,
	events.EpollCreate:           pb.EventId_epoll_create,
	events.EpollCtlOld:           pb.EventId_epoll_ctl_old,
	events.EpollWaitOld:          pb.EventId_epoll_wait_old,
	events.RemapFilePages:        pb.EventId_remap_file_pages,
	events.Getdents64:            pb.EventId_getdents64,
	events.SetTidAddress:         pb.EventId_set_tid_address,
	events.RestartSyscall:        pb.EventId_restart_syscall,
	events.Semtimedop:            pb.EventId_semtimedop,
	events.Fadvise64:             pb.EventId_fadvise64,
	events.TimerCreate:           pb.EventId_timer_create,
	events.TimerSettime:          pb.EventId_timer_settime,
	events.TimerGettime:          pb.EventId_timer_gettime,
	events.TimerGetoverrun:       pb.EventId_timer_getoverrun,
	events.TimerDelete:           pb.EventId_timer_delete,
	events.ClockSettime:          pb.EventId_clock_settime,
	events.ClockGettime:          pb.EventId_clock_gettime,
	events.ClockGetres:           pb.EventId_clock_getres,
	events.ClockNanosleep:        pb.EventId_clock_nanosleep,
	events.ExitGroup:             pb.EventId_exit_group,
	events.EpollWait:             pb.EventId_epoll_wait,
	events.EpollCtl:              pb.EventId_epoll_ctl,
	events.Tgkill:                pb.EventId_tgkill,
	events.Utimes:                pb.EventId_utimes,
	events.Vserver:               pb.EventId_vserver,
	events.Mbind:                 pb.EventId_mbind,
	events.SetMempolicy:          pb.EventId_set_mempolicy,
	events.GetMempolicy:          pb.EventId_get_mempolicy,
	events.MqOpen:                pb.EventId_mq_open,
	events.MqUnlink:              pb.EventId_mq_unlink,
	events.MqTimedsend:           pb.EventId_mq_timedsend,
	events.MqTimedreceive:        pb.EventId_mq_timedreceive,
	events.MqNotify:              pb.EventId_mq_notify,
	events.MqGetsetattr:          pb.EventId_mq_getsetattr,
	events.KexecLoad:             pb.EventId_kexec_load,
	events.Waitid:                pb.EventId_waitid,
	events.AddKey:                pb.EventId_add_key,
	events.RequestKey:            pb.EventId_request_key,
	events.Keyctl:                pb.EventId_keyctl,
	events.IoprioSet:             pb.EventId_ioprio_set,
	events.IoprioGet:             pb.EventId_ioprio_get,
	events.InotifyInit:           pb.EventId_inotify_init,
	events.InotifyAddWatch:       pb.EventId_inotify_add_watch,
	events.InotifyRmWatch:        pb.EventId_inotify_rm_watch,
	events.MigratePages:          pb.EventId_migrate_pages,
	events.Openat:                pb.EventId_openat,
	events.Mkdirat:               pb.EventId_mkdirat,
	events.Mknodat:               pb.EventId_mknodat,
	events.Fchownat:              pb.EventId_fchownat,
	events.Futimesat:             pb.EventId_futimesat,
	events.Newfstatat:            pb.EventId_newfstatat,
	events.Unlinkat:              pb.EventId_unlinkat,
	events.Renameat:              pb.EventId_renameat,
	events.Linkat:                pb.EventId_linkat,
	events.Symlinkat:             pb.EventId_symlinkat,
	events.Readlinkat:            pb.EventId_readlinkat,
	events.Fchmodat:              pb.EventId_fchmodat,
	events.Faccessat:             pb.EventId_faccessat,
	events.Pselect6:              pb.EventId_pselect6,
	events.Ppoll:                 pb.EventId_ppoll,
	events.Unshare:               pb.EventId_unshare,
	events.SetRobustList:         pb.EventId_set_robust_list,
	events.GetRobustList:         pb.EventId_get_robust_list,
	events.Splice:                pb.EventId_splice,
	events.Tee:                   pb.EventId_tee,
	events.SyncFileRange:         pb.EventId_sync_file_range,
	events.Vmsplice:              pb.EventId_vmsplice,
	events.MovePages:             pb.EventId_move_pages,
	events.Utimensat:             pb.EventId_utimensat,
	events.EpollPwait:            pb.EventId_epoll_pwait,
	events.Signalfd:              pb.EventId_signalfd,
	events.TimerfdCreate:         pb.EventId_timerfd_create,
	events.Eventfd:               pb.EventId_eventfd,
	events.Fallocate:             pb.EventId_fallocate,
	events.TimerfdSettime:        pb.EventId_timerfd_settime,
	events.TimerfdGettime:        pb.EventId_timerfd_gettime,
	events.Accept4:               pb.EventId_accept4,
	events.Signalfd4:             pb.EventId_signalfd4,
	events.Eventfd2:              pb.EventId_eventfd2,
	events.EpollCreate1:          pb.EventId_epoll_create1,
	events.Dup3:                  pb.EventId_dup3,
	events.Pipe2:                 pb.EventId_pipe2,
	events.InotifyInit1:          pb.EventId_inotify_init1,
	events.Preadv:                pb.EventId_preadv,
	events.Pwritev:               pb.EventId_pwritev,
	events.RtTgsigqueueinfo:      pb.EventId_rt_tgsigqueueinfo,
	events.PerfEventOpen:         pb.EventId_perf_event_open,
	events.Recvmmsg:              pb.EventId_recvmmsg,
	events.FanotifyInit:          pb.EventId_fanotify_init,
	events.FanotifyMark:          pb.EventId_fanotify_mark,
	events.Prlimit64:             pb.EventId_prlimit64,
	events.NameToHandleAt:        pb.EventId_name_to_handle_at,
	events.OpenByHandleAt:        pb.EventId_open_by_handle_at,
	events.ClockAdjtime:          pb.EventId_clock_adjtime,
	events.Syncfs:                pb.EventId_syncfs,
	events.Sendmmsg:              pb.EventId_sendmmsg,
	events.Setns:                 pb.EventId_setns,
	events.Getcpu:                pb.EventId_getcpu,
	events.ProcessVmReadv:        pb.EventId_process_vm_readv,
	events.ProcessVmWritev:       pb.EventId_process_vm_writev,
	events.Kcmp:                  pb.EventId_kcmp,
	events.FinitModule:           pb.EventId_finit_module,
	events.SchedSetattr:          pb.EventId_sched_setattr,
	events.SchedGetattr:          pb.EventId_sched_getattr,
	events.Renameat2:             pb.EventId_renameat2,
	events.Seccomp:               pb.EventId_seccomp,
	events.Getrandom:             pb.EventId_getrandom,
	events.MemfdCreate:           pb.EventId_memfd_create,
	events.KexecFileLoad:         pb.EventId_kexec_file_load,
	events.Bpf:                   pb.EventId_bpf,
	events.Execveat:              pb.EventId_execveat,
	events.Userfaultfd:           pb.EventId_userfaultfd,
	events.Membarrier:            pb.EventId_membarrier,
	events.Mlock2:                pb.EventId_mlock2,
	events.CopyFileRange:         pb.EventId_copy_file_range,
	events.Preadv2:               pb.EventId_preadv2,
	events.Pwritev2:              pb.EventId_pwritev2,
	events.PkeyMprotect:          pb.EventId_pkey_mprotect,
	events.PkeyAlloc:             pb.EventId_pkey_alloc,
	events.PkeyFree:              pb.EventId_pkey_free,
	events.Statx:                 pb.EventId_statx,
	events.IoPgetevents:          pb.EventId_io_pgetevents,
	events.Rseq:                  pb.EventId_rseq,
	events.PidfdSendSignal:       pb.EventId_pidfd_send_signal,
	events.IoUringSetup:          pb.EventId_io_uring_setup,
	events.IoUringEnter:          pb.EventId_io_uring_enter,
	events.IoUringRegister:       pb.EventId_io_uring_register,
	events.OpenTree:              pb.EventId_open_tree,
	events.MoveMount:             pb.EventId_move_mount,
	events.Fsopen:                pb.EventId_fsopen,
	events.Fsconfig:              pb.EventId_fsconfig,
	events.Fsmount:               pb.EventId_fsmount,
	events.Fspick:                pb.EventId_fspick,
	events.PidfdOpen:             pb.EventId_pidfd_open,
	events.Clone3:                pb.EventId_clone3,
	events.CloseRange:            pb.EventId_close_range,
	events.Openat2:               pb.EventId_openat2,
	events.PidfdGetfd:            pb.EventId_pidfd_getfd,
	events.Faccessat2:            pb.EventId_faccessat2,
	events.ProcessMadvise:        pb.EventId_process_madvise,
	events.EpollPwait2:           pb.EventId_epoll_pwait2,
	events.MountSetattr:          pb.EventId_mount_setattr,
	events.QuotactlFd:            pb.EventId_quotactl_fd,
	events.LandlockCreateRuleset: pb.EventId_landlock_create_ruleset,
	events.LandlockAddRule:       pb.EventId_landlock_add_rule,
	events.LandlockRestrictSelf:  pb.EventId_landlock_restrict_self,
	events.MemfdSecret:           pb.EventId_memfd_secret,
	events.ProcessMrelease:       pb.EventId_process_mrelease,
	events.Waitpid:               pb.EventId_waitpid,
	events.Oldfstat:              pb.EventId_oldfstat,
	events.Break:                 pb.EventId_break,
	events.Oldstat:               pb.EventId_oldstat,
	events.Umount:                pb.EventId_umount,
	events.Stime:                 pb.EventId_stime,
	events.Stty:                  pb.EventId_stty,
	events.Gtty:                  pb.EventId_gtty,
	events.Nice:                  pb.EventId_nice,
	events.Ftime:                 pb.EventId_ftime,
	events.Prof:                  pb.EventId_prof,
	events.Signal:                pb.EventId_signal,
	events.Lock:                  pb.EventId_lock,
	events.Mpx:                   pb.EventId_mpx,
	events.Ulimit:                pb.EventId_ulimit,
	events.Oldolduname:           pb.EventId_oldolduname,
	events.Sigaction:             pb.EventId_sigaction,
	events.Sgetmask:              pb.EventId_sgetmask,
	events.Ssetmask:              pb.EventId_ssetmask,
	events.Sigsuspend:            pb.EventId_sigsuspend,
	events.Sigpending:            pb.EventId_sigpending,
	events.Oldlstat:              pb.EventId_oldlstat,
	events.Readdir:               pb.EventId_readdir,
	events.Profil:                pb.EventId_profil,
	events.Socketcall:            pb.EventId_socketcall,
	events.Olduname:              pb.EventId_olduname,
	events.Idle:                  pb.EventId_idle,
	events.Vm86old:               pb.EventId_vm86old,
	events.Ipc:                   pb.EventId_ipc,
	events.Sigreturn:             pb.EventId_sigreturn,
	events.Sigprocmask:           pb.EventId_sigprocmask,
	events.Bdflush:               pb.EventId_bdflush,
	events.Afs_syscall:           pb.EventId_afs_syscall,
	events.Llseek:                pb.EventId_llseek,
	events.OldSelect:             pb.EventId_old_select,
	events.Vm86:                  pb.EventId_vm86,
	events.OldGetrlimit:          pb.EventId_old_getrlimit,
	events.Mmap2:                 pb.EventId_mmap2,
	events.Truncate64:            pb.EventId_truncate64,
	events.Ftruncate64:           pb.EventId_ftruncate64,
	events.Stat64:                pb.EventId_stat64,
	events.Lstat64:               pb.EventId_lstat64,
	events.Fstat64:               pb.EventId_fstat64,
	events.Lchown16:              pb.EventId_lchown16,
	events.Getuid16:              pb.EventId_getuid16,
	events.Getgid16:              pb.EventId_getgid16,
	events.Geteuid16:             pb.EventId_geteuid16,
	events.Getegid16:             pb.EventId_getegid16,
	events.Setreuid16:            pb.EventId_setreuid16,
	events.Setregid16:            pb.EventId_setregid16,
	events.Getgroups16:           pb.EventId_getgroups16,
	events.Setgroups16:           pb.EventId_setgroups16,
	events.Fchown16:              pb.EventId_fchown16,
	events.Setresuid16:           pb.EventId_setresuid16,
	events.Getresuid16:           pb.EventId_getresuid16,
	events.Setresgid16:           pb.EventId_setresgid16,
	events.Getresgid16:           pb.EventId_getresgid16,
	events.Chown16:               pb.EventId_chown16,
	events.Setuid16:              pb.EventId_setuid16,
	events.Setgid16:              pb.EventId_setgid16,
	events.Setfsuid16:            pb.EventId_setfsuid16,
	events.Setfsgid16:            pb.EventId_setfsgid16,
	events.Fcntl64:               pb.EventId_fcntl64,
	events.Sendfile32:            pb.EventId_sendfile32,
	events.Statfs64:              pb.EventId_statfs64,
	events.Fstatfs64:             pb.EventId_fstatfs64,
	events.Fadvise64_64:          pb.EventId_fadvise64_64,
	events.ClockGettime32:        pb.EventId_clock_gettime32,
	events.ClockSettime32:        pb.EventId_clock_settime32,
	events.ClockAdjtime64:        pb.EventId_clock_adjtime64,
	events.ClockGetresTime32:     pb.EventId_clock_getres_time32,
	events.ClockNanosleepTime32:  pb.EventId_clock_nanosleep_time32,
	events.TimerGettime32:        pb.EventId_timer_gettime32,
	events.TimerSettime32:        pb.EventId_timer_settime32,
	events.TimerfdGettime32:      pb.EventId_timerfd_gettime32,
	events.TimerfdSettime32:      pb.EventId_timerfd_settime32,
	events.UtimensatTime32:       pb.EventId_utimensat_time32,
	events.Pselect6Time32:        pb.EventId_pselect6_time32,
	events.PpollTime32:           pb.EventId_ppoll_time32,
	events.IoPgeteventsTime32:    pb.EventId_io_pgetevents_time32,
	events.RecvmmsgTime32:        pb.EventId_recvmmsg_time32,
	events.MqTimedsendTime32:     pb.EventId_mq_timedsend_time32,
	events.MqTimedreceiveTime32:  pb.EventId_mq_timedreceive_time32,
	events.RtSigtimedwaitTime32:  pb.EventId_rt_sigtimedwait_time32,
	events.FutexTime32:           pb.EventId_futex_time32,
	events.SchedRrGetInterval32:  pb.EventId_sched_rr_get_interval_time32,

	// Common events translation section
	events.NetPacketBase:                pb.EventId_net_packet_base,
	events.NetPacketIPBase:              pb.EventId_net_packet_ip_base,
	events.NetPacketTCPBase:             pb.EventId_net_packet_tcp_base,
	events.NetPacketUDPBase:             pb.EventId_net_packet_udp_base,
	events.NetPacketICMPBase:            pb.EventId_net_packet_icmp_base,
	events.NetPacketICMPv6Base:          pb.EventId_net_packet_icmpv6_base,
	events.NetPacketDNSBase:             pb.EventId_net_packet_dns_base,
	events.NetPacketHTTPBase:            pb.EventId_net_packet_http_base,
	events.NetPacketCapture:             pb.EventId_net_packet_capture,
	events.NetPacketFlow:                pb.EventId_net_packet_flow,
	events.MaxNetID:                     pb.EventId_max_net_id,
	events.SysEnter:                     pb.EventId_sys_enter,
	events.SysExit:                      pb.EventId_sys_exit,
	events.SchedProcessFork:             pb.EventId_sched_process_fork,
	events.SchedProcessExec:             pb.EventId_sched_process_exec,
	events.SchedProcessExit:             pb.EventId_sched_process_exit,
	events.SchedSwitch:                  pb.EventId_sched_switch,
	events.DoExit:                       pb.EventId_do_exit,
	events.CapCapable:                   pb.EventId_cap_capable,
	events.VfsWrite:                     pb.EventId_vfs_write,
	events.VfsWritev:                    pb.EventId_vfs_writev,
	events.VfsRead:                      pb.EventId_vfs_read,
	events.VfsReadv:                     pb.EventId_vfs_readv,
	events.MemProtAlert:                 pb.EventId_mem_prot_alert,
	events.CommitCreds:                  pb.EventId_commit_creds,
	events.SwitchTaskNS:                 pb.EventId_switch_task_ns,
	events.MagicWrite:                   pb.EventId_magic_write,
	events.CgroupAttachTask:             pb.EventId_cgroup_attach_task,
	events.CgroupMkdir:                  pb.EventId_cgroup_mkdir,
	events.CgroupRmdir:                  pb.EventId_cgroup_rmdir,
	events.SecurityBprmCheck:            pb.EventId_security_bprm_check,
	events.SecurityFileOpen:             pb.EventId_security_file_open,
	events.SecurityInodeUnlink:          pb.EventId_security_inode_unlink,
	events.SecuritySocketCreate:         pb.EventId_security_socket_create,
	events.SecuritySocketListen:         pb.EventId_security_socket_listen,
	events.SecuritySocketConnect:        pb.EventId_security_socket_connect,
	events.SecuritySocketAccept:         pb.EventId_security_socket_accept,
	events.SecuritySocketBind:           pb.EventId_security_socket_bind,
	events.SecuritySocketSetsockopt:     pb.EventId_security_socket_setsockopt,
	events.SecuritySbMount:              pb.EventId_security_sb_mount,
	events.SecurityBPF:                  pb.EventId_security_bpf,
	events.SecurityBPFMap:               pb.EventId_security_bpf_map,
	events.SecurityKernelReadFile:       pb.EventId_security_kernel_read_file,
	events.SecurityInodeMknod:           pb.EventId_security_inode_mknod,
	events.SecurityPostReadFile:         pb.EventId_security_post_read_file,
	events.SecurityInodeSymlinkEventId:  pb.EventId_security_inode_symlink_event_id,
	events.SecurityMmapFile:             pb.EventId_security_mmap_file,
	events.SecurityFileMprotect:         pb.EventId_security_file_mprotect,
	events.SocketDup:                    pb.EventId_socket_dup,
	events.HiddenInodes:                 pb.EventId_hidden_inodes,
	events.KernelWrite:                  pb.EventId_kernel_write,
	events.ProcCreate:                   pb.EventId_proc_create,
	events.KprobeAttach:                 pb.EventId_kprobe_attach,
	events.CallUsermodeHelper:           pb.EventId_call_usermode_helper,
	events.DirtyPipeSplice:              pb.EventId_dirty_pipe_splice,
	events.DebugfsCreateFile:            pb.EventId_debugfs_create_file,
	events.SyscallTableCheck:            pb.EventId_syscall_table_check,
	events.DebugfsCreateDir:             pb.EventId_debugfs_create_dir,
	events.DeviceAdd:                    pb.EventId_device_add,
	events.RegisterChrdev:               pb.EventId_register_chrdev,
	events.SharedObjectLoaded:           pb.EventId_shared_object_loaded,
	events.DoInitModule:                 pb.EventId_do_init_module,
	events.SocketAccept:                 pb.EventId_socket_accept,
	events.LoadElfPhdrs:                 pb.EventId_load_elf_phdrs,
	events.HookedProcFops:               pb.EventId_hooked_proc_fops,
	events.PrintNetSeqOps:               pb.EventId_print_net_seq_ops,
	events.TaskRename:                   pb.EventId_task_rename,
	events.SecurityInodeRename:          pb.EventId_security_inode_rename,
	events.DoSigaction:                  pb.EventId_do_sigaction,
	events.BpfAttach:                    pb.EventId_bpf_attach,
	events.KallsymsLookupName:           pb.EventId_kallsyms_lookup_name,
	events.DoMmap:                       pb.EventId_do_mmap,
	events.PrintMemDump:                 pb.EventId_print_mem_dump,
	events.VfsUtimes:                    pb.EventId_vfs_utimes,
	events.DoTruncate:                   pb.EventId_do_truncate,
	events.FileModification:             pb.EventId_file_modification,
	events.InotifyWatch:                 pb.EventId_inotify_watch,
	events.SecurityBpfProg:              pb.EventId_security_bpf_prog,
	events.ProcessExecuteFailed:         pb.EventId_process_execute_failed,
	events.SecurityPathNotify:           pb.EventId_security_path_notify,
	events.SetFsPwd:                     pb.EventId_set_fs_pwd,
	events.HiddenKernelModuleSeeker:     pb.EventId_hidden_kernel_module_seeker,
	events.ModuleLoad:                   pb.EventId_module_load,
	events.ModuleFree:                   pb.EventId_module_free,
	events.ExecuteFinished:              pb.EventId_execute_finished,
	events.ProcessExecuteFailedInternal: pb.EventId_process_execute_failed_internal,

	// Events from user-space translation section
	events.NetPacketIPv4:         pb.EventId_net_packet_ipv4,
	events.NetPacketIPv6:         pb.EventId_net_packet_ipv6,
	events.NetPacketTCP:          pb.EventId_net_packet_tcp,
	events.NetPacketUDP:          pb.EventId_net_packet_udp,
	events.NetPacketICMP:         pb.EventId_net_packet_icmp,
	events.NetPacketICMPv6:       pb.EventId_net_packet_icmpv6,
	events.NetPacketDNS:          pb.EventId_net_packet_dns,
	events.NetPacketDNSRequest:   pb.EventId_net_packet_dns_request,
	events.NetPacketDNSResponse:  pb.EventId_net_packet_dns_response,
	events.NetPacketHTTP:         pb.EventId_net_packet_http,
	events.NetPacketHTTPRequest:  pb.EventId_net_packet_http_request,
	events.NetPacketHTTPResponse: pb.EventId_net_packet_http_response,
	events.NetFlowEnd:            pb.EventId_net_flow_end,
	events.NetFlowTCPBegin:       pb.EventId_net_flow_tcp_begin,
	events.NetFlowTCPEnd:         pb.EventId_net_flow_tcp_end,
	events.MaxUserNetID:          pb.EventId_max_user_net_id,
	events.NetTCPConnect:         pb.EventId_net_tcp_connect,
	events.InitNamespaces:        pb.EventId_init_namespaces,
	events.ContainerCreate:       pb.EventId_container_create,
	events.ContainerRemove:       pb.EventId_container_remove,
	events.ExistingContainer:     pb.EventId_existing_container,
	events.HookedSyscall:         pb.EventId_hooked_syscall,
	events.HookedSeqOps:          pb.EventId_hooked_seq_ops,
	events.SymbolsLoaded:         pb.EventId_symbols_loaded,
	events.SymbolsCollision:      pb.EventId_symbols_collision,
	events.HiddenKernelModule:    pb.EventId_hidden_kernel_module,
	events.FtraceHook:            pb.EventId_ftrace_hook,
}

type TraceeService struct {
	pb.UnimplementedTraceeServiceServer
	tracee *tracee.Tracee
}

func (s *TraceeService) StreamEvents(in *pb.StreamEventsRequest, grpcStream pb.TraceeService_StreamEventsServer) error {
	var stream *streams.Stream
	var err error

	if len(in.Policies) == 0 {
		stream = s.tracee.SubscribeAll()
	} else {
		stream, err = s.tracee.Subscribe(in.Policies)
		if err != nil {
			return err
		}
	}
	defer s.tracee.Unsubscribe(stream)

	mask := fmutils.NestedMaskFromPaths(in.GetMask().GetPaths())

	for e := range stream.ReceiveEvents() {
		// TODO: this conversion is temporary, we will use the new event structure
		// on tracee internals, so the event received by the stream will already be a proto
		eventProto, err := convertTraceeEventToProto(e)
		if err != nil {
			logger.Errorw("error can't create event proto: " + err.Error())
			continue
		}

		mask.Filter(eventProto)

		err = grpcStream.Send(&pb.StreamEventsResponse{Event: eventProto})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *TraceeService) EnableEvent(ctx context.Context, in *pb.EnableEventRequest) (*pb.EnableEventResponse, error) {
	err := s.tracee.EnableEvent(in.Name)
	if err != nil {
		return nil, err
	}

	return &pb.EnableEventResponse{}, nil
}

func (s *TraceeService) DisableEvent(ctx context.Context, in *pb.DisableEventRequest) (*pb.DisableEventResponse, error) {
	err := s.tracee.DisableEvent(in.Name)
	if err != nil {
		return nil, err
	}

	return &pb.DisableEventResponse{}, nil
}

func (s *TraceeService) GetEventDefinitions(ctx context.Context, in *pb.GetEventDefinitionsRequest) (*pb.GetEventDefinitionsResponse, error) {
	definitions, err := getDefinitions(in)
	if err != nil {
		return nil, err
	}

	out := make([]*pb.EventDefinition, 0, len(definitions))

	for _, d := range definitions {
		ed := convertDefinitionToProto(d)
		out = append(out, ed)
	}

	return &pb.GetEventDefinitionsResponse{
		Definitions: out,
	}, nil
}

func (s *TraceeService) GetVersion(ctx context.Context, in *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return &pb.GetVersionResponse{Version: version.GetVersion()}, nil
}

func getDefinitions(in *pb.GetEventDefinitionsRequest) ([]events.Definition, error) {
	if len(in.EventNames) == 0 {
		return events.Core.GetDefinitions(), nil
	}

	definitions := make([]events.Definition, 0, len(in.EventNames))

	for _, name := range in.EventNames {
		definition := events.Core.GetDefinitionByName(name)
		if definition.NotValid() {
			return nil, fmt.Errorf("event %s not found", name)
		}

		definitions = append(definitions, definition)
	}

	return definitions, nil
}

func convertDefinitionToProto(d events.Definition) *pb.EventDefinition {
	v := &pb.Version{
		Major: d.GetVersion().Major(),
		Minor: d.GetVersion().Minor(),
		Patch: d.GetVersion().Patch(),
	}

	return &pb.EventDefinition{
		Id:          int32(d.GetID()),
		Name:        d.GetName(),
		Version:     v,
		Description: d.GetDescription(),
		Tags:        d.GetSets(),
		// threat description is empty because it is the same as the event definition description
		Threat: getThreat("", d.GetProperties()),
	}
}

func getExternalID(e trace.Event) pb.EventId {
	// Only use translation table if is built-in events (below 10,000)
	if e.EventID <= int(events.MaxBuiltinID) {
		idExternal := EventTranslationTable[events.ID(e.EventID)]
		return idExternal
	}
	return pb.EventId(e.EventID)
}

func convertTraceeEventToProto(e trace.Event) (*pb.Event, error) {
	process := getProcess(e)
	container := getContainer(e)
	k8s := getK8s(e)
	idExternal := getExternalID(e)

	var eventWorkload *pb.Workload
	if process != nil || container != nil || k8s != nil {
		eventWorkload = &pb.Workload{
			Process:   process,
			Container: container,
			K8S:       k8s,
		}
	}

	eventData, err := getEventData(e)
	if err != nil {
		return nil, err
	}

	var threat *pb.Threat
	if e.Metadata != nil {
		threat = getThreat(e.Metadata.Description, e.Metadata.Properties)
	}

	triggerEvent, err := getTriggerBy(e.Args)
	if err != nil {
		return nil, err
	}

	event := &pb.Event{
		Id:   idExternal,
		Name: e.EventName,
		Policies: &pb.Policies{
			Matched: e.MatchedPolicies,
		},
		Workload:    eventWorkload,
		Data:        eventData,
		Threat:      threat,
		TriggeredBy: triggerEvent,
	}

	if e.Timestamp != 0 {
		event.Timestamp = timestamppb.New(time.Unix(0, int64(e.Timestamp)))
	}

	return event, nil
}

func getProcess(e trace.Event) *pb.Process {
	var userStackTrace *pb.UserStackTrace

	if len(e.StackAddresses) > 0 {
		userStackTrace = &pb.UserStackTrace{
			Addresses: getStackAddress(e.StackAddresses),
		}
	}

	var threadStartTime *timestamp.Timestamp
	if e.ThreadStartTime != 0 {
		threadStartTime = timestamppb.New(time.Unix(0, int64(e.ThreadStartTime)))
	}

	var executable *pb.Executable
	if e.Executable.Path != "" {
		executable = &pb.Executable{Path: e.Executable.Path}
	}

	ancestors := getAncestors(e)

	return &pb.Process{
		Executable: executable,
		UniqueId:   wrapperspb.UInt32(e.ProcessEntityId),
		HostPid:    wrapperspb.UInt32(uint32(e.HostProcessID)),
		Pid:        wrapperspb.UInt32(uint32(e.ProcessID)),
		RealUser: &pb.User{
			Id: wrapperspb.UInt32(uint32(e.UserID)),
		},
		Thread: &pb.Thread{
			StartTime:      threadStartTime,
			Name:           e.ProcessName,
			UniqueId:       wrapperspb.UInt32(e.ThreadEntityId),
			HostTid:        wrapperspb.UInt32(uint32(e.HostThreadID)),
			Tid:            wrapperspb.UInt32(uint32(e.ThreadID)),
			Syscall:        e.Syscall,
			Compat:         e.ContextFlags.ContainerStarted,
			UserStackTrace: userStackTrace,
		},
		Ancestors: ancestors,
	}
}

func getAncestors(e trace.Event) []*pb.Process {
	var ancestors []*pb.Process
	if e.ParentEntityId != 0 {
		ancestors = append(ancestors, &pb.Process{
			UniqueId: wrapperspb.UInt32(e.ParentEntityId),
			HostPid:  wrapperspb.UInt32(uint32(e.HostParentProcessID)),
			Pid:      wrapperspb.UInt32(uint32(e.ParentProcessID)),
		})
	}
	return ancestors
}

func getContainer(e trace.Event) *pb.Container {
	if e.Container.ID == "" && e.Container.Name == "" {
		return nil
	}

	container := &pb.Container{
		Id:   e.Container.ID,
		Name: e.Container.Name,
	}

	if e.Container.ImageName != "" {
		var repoDigest []string
		if e.Container.ImageDigest != "" {
			repoDigest = []string{e.Container.ImageDigest}
		}

		container.Image = &pb.ContainerImage{
			Name:        e.Container.ImageName,
			RepoDigests: repoDigest,
		}
	}

	return container
}

func getK8s(e trace.Event) *pb.K8S {
	if e.Kubernetes.PodName == "" &&
		e.Kubernetes.PodUID == "" &&
		e.Kubernetes.PodNamespace == "" {
		return nil
	}

	return &pb.K8S{
		Namespace: &pb.K8SNamespace{
			Name: e.Kubernetes.PodNamespace,
		},
		Pod: &pb.Pod{
			Name: e.Kubernetes.PodName,
			Uid:  e.Kubernetes.PodUID,
		},
	}
}

func getThreat(description string, metadata map[string]interface{}) *pb.Threat {
	if metadata == nil {
		return nil
	}
	// if metadata doesn't contain severity, it's not a threat,
	// severity is set when we have an event created from a signature
	// pkg/ebpf/fiding.go
	// pkg/cmd/initialize/sigs.go
	_, ok := metadata["Severity"]
	if !ok {
		return nil
	}

	var (
		mitreTactic        string
		mitreTechniqueId   string
		mitreTechniqueName string
		name               string
	)

	if _, ok := metadata["Category"]; ok {
		if val, ok := metadata["Category"].(string); ok {
			mitreTactic = val
		}
	}

	if _, ok := metadata["external_id"]; ok {
		if val, ok := metadata["external_id"].(string); ok {
			mitreTechniqueId = val
		}
	}

	if _, ok := metadata["Technique"]; ok {
		if val, ok := metadata["Technique"].(string); ok {
			mitreTechniqueName = val
		}
	}

	if _, ok := metadata["signatureName"]; ok {
		if val, ok := metadata["signatureName"].(string); ok {
			name = val
		}
	}

	properties := make(map[string]string)

	for k, v := range metadata {
		if k == "Category" ||
			k == "external_id" ||
			k == "Technique" ||
			k == "Severity" ||
			k == "signatureName" {
			continue
		}

		properties[k] = fmt.Sprint(v)
	}

	return &pb.Threat{
		Description: description,
		Mitre: &pb.Mitre{
			Tactic: &pb.MitreTactic{
				Name: mitreTactic,
			},
			Technique: &pb.MitreTechnique{
				Id:   mitreTechniqueId,
				Name: mitreTechniqueName,
			},
		},
		Severity:   getSeverity(metadata),
		Name:       name,
		Properties: properties,
	}
}

func getTriggerBy(args []trace.Argument) (*pb.TriggeredBy, error) {
	var triggeredByArg *trace.Argument
	triggerEvent := &pb.TriggeredBy{}

	for i := range args {
		if args[i].ArgMeta.Name == "triggeredBy" {
			triggeredByArg = &args[i]
			break
		}
	}
	if triggeredByArg == nil {
		return triggerEvent, nil
	}

	m, ok := triggeredByArg.Value.(map[string]interface{})
	if !ok {
		return nil, errfmt.Errorf("error getting triggering event: %v", triggeredByArg.Value)
	}

	id, ok := m["id"].(int)
	if !ok {
		return nil, errfmt.Errorf("error getting id of triggering event: %v", m)
	}
	triggerEvent.Id = uint32(id)

	name, ok := m["name"].(string)
	if !ok {
		return nil, errfmt.Errorf("error getting name of triggering event: %v", m)
	}
	triggerEvent.Name = name

	triggerEventArgs, ok := m["args"].([]trace.Argument)
	if !ok {
		return nil, errfmt.Errorf("error getting args of triggering event: %v", m)
	}

	data := make([]*pb.EventValue, 0)

	for _, arg := range triggerEventArgs {
		eventValue, err := getEventValue(arg)
		if err != nil {
			return nil, err
		}

		eventValue.Name = arg.ArgMeta.Name
		data = append(data, eventValue)
	}

	if events.Core.GetDefinitionByID(events.ID(id)).IsSyscall() {
		data = append(data, &pb.EventValue{
			Name: "returnValue",
			Value: &pb.EventValue_Int64{
				Int64: int64(m["returnValue"].(int)),
			},
		})
	}

	triggerEvent.Data = data

	return triggerEvent, nil
}

func getSeverity(metadata map[string]interface{}) pb.Severity {
	severityValue, ok := metadata["Severity"].(int)
	if ok {
		switch severityValue {
		case 0:
			return pb.Severity_INFO
		case 1:
			return pb.Severity_LOW
		case 2:
			return pb.Severity_MEDIUM
		case 3:
			return pb.Severity_HIGH
		case 4:
			return pb.Severity_CRITICAL
		}
	}

	return pb.Severity_INFO
}

func getStackAddress(stackAddresses []uint64) []*pb.StackAddress {
	var out []*pb.StackAddress
	for _, addr := range stackAddresses {
		out = append(out, &pb.StackAddress{Address: addr})
	}

	return out
}
