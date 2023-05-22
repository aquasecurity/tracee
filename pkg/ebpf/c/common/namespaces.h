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
    struct mnt_namespace *mntns = READ_KERN(ns->mnt_ns);
    return READ_KERN(mntns->ns.inum);
}

statfunc u32 get_pid_ns_for_children_id(struct nsproxy *ns)
{
    struct pid_namespace *pidns = READ_KERN(ns->pid_ns_for_children);
    return READ_KERN(pidns->ns.inum);
}

statfunc u32 get_uts_ns_id(struct nsproxy *ns)
{
    struct uts_namespace *uts_ns = READ_KERN(ns->uts_ns);
    return READ_KERN(uts_ns->ns.inum);
}

statfunc u32 get_ipc_ns_id(struct nsproxy *ns)
{
    struct ipc_namespace *ipc_ns = READ_KERN(ns->ipc_ns);
    return READ_KERN(ipc_ns->ns.inum);
}

statfunc u32 get_net_ns_id(struct nsproxy *ns)
{
    struct net *net_ns = READ_KERN(ns->net_ns);
    return READ_KERN(net_ns->ns.inum);
}

statfunc u32 get_cgroup_ns_id(struct nsproxy *ns)
{
    struct cgroup_namespace *cgroup_ns = READ_KERN(ns->cgroup_ns);
    return READ_KERN(cgroup_ns->ns.inum);
}

#endif
