#ifndef __COMMON_NAMESPACES_H__
#define __COMMON_NAMESPACES_H__

#include <vmlinux.h>

#include <common/common.h>

// PROTOTYPES

statfunc u32 get_mnt_ns_id(struct nsproxy *);
statfunc u32 get_pid_ns_for_children_id(struct nsproxy *);
statfunc u32 get_uts_ns_id(struct nsproxy *);
statfunc u32 get_ipc_ns_id(struct nsproxy *);
statfunc u32 get_net_ns_id(struct nsproxy *);
statfunc u32 get_cgroup_ns_id(struct nsproxy *);

// FUNCTIONS

statfunc u32 get_mnt_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, mnt_ns, ns.inum);
}

statfunc u32 get_pid_ns_for_children_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, pid_ns_for_children, ns.inum);
}

statfunc u32 get_uts_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, uts_ns, ns.inum);
}

statfunc u32 get_ipc_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, ipc_ns, ns.inum);
}

statfunc u32 get_net_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, net_ns, ns.inum);
}

statfunc u32 get_cgroup_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, cgroup_ns, ns.inum);
}

#endif
