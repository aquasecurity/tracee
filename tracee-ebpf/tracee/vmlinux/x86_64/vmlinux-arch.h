#ifndef __VMLINUX_ARCH_H__
#define __VMLINUX_ARCH_H__

#include <vmlinux-core.h>
#include <vmlinux-flavored.h>

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct thread_info {
	u32 status;
};

struct task_struct {
	struct thread_info         thread_info;
	unsigned int               flags;
	short unsigned int         migration_flags;
	struct mm_struct *         mm;
	int                        exit_code;
	long unsigned int          atomic_flags;
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
	unsigned int               sas_ss_flags;
	unsigned int               psi_flags;
	struct css_set *           cgroups;
};

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_ARCH_H__ */
