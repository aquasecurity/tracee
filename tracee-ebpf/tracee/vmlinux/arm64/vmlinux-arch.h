#ifndef __VMLINUX_ARCH_H__
#define __VMLINUX_ARCH_H__

#include <vmlinux-core.h>
#include <vmlinux-flavored.h>

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

struct thread_info {
	long unsigned int flags;
};

struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
	u64 orig_x0;
	s32 syscallno;
	u32 unused2;
	u64 orig_addr_limit;
	u64 pmr_save;
	u64 stackframe[2];
	u64 lockdep_hardirqs;
	u64 exit_rcu;
};

struct task_struct {
	struct thread_info         thread_info;
	unsigned int               flags;
	struct mm_struct *         mm;
	int                        exit_code;
	pid_t                      pid;
	pid_t                      tgid;
	struct task_struct *       real_parent;
	struct task_struct *       group_leader;
	struct pid *               thread_pid;
	struct list_head           thread_group;
	const struct cred  *       real_cred;
	char                       comm[16];
	struct files_struct *      files;
	struct nsproxy *           nsproxy;
	struct css_set *           cgroups;
};

#pragma clang attribute pop

#endif /* __VMLINUX_ARCH_H__ */
