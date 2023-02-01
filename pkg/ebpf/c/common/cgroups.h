#ifndef __TRACEE_CGROUPS_H__
#define __TRACEE_CGROUPS_H__

#ifndef CORE
    #include <linux/types.h>
    #include <linux/cgroup.h>
    #include <linux/sched.h>
#else
    #include <vmlinux.h>
#endif
#include <bpf/bpf_helpers.h>
#include "common/common.h"

static __always_inline const char *get_cgroup_dirname(struct cgroup *cgrp)
{
    struct kernfs_node *kn = READ_KERN(cgrp->kn);

    if (kn == NULL)
        return NULL;

    return READ_KERN(kn->name);
}

static __always_inline const u64 get_cgroup_id(struct cgroup *cgrp)
{
    struct kernfs_node *kn = READ_KERN(cgrp->kn);

    if (kn == NULL)
        return 0;

    u64 id; // was union kernfs_node_id before 5.5, can read it as u64 in both situations

#ifdef CORE
    if (bpf_core_type_exists(union kernfs_node_id)) {
        struct kernfs_node___older_v55 *kn_old = (void *) kn;
        struct kernfs_node___rh8 *kn_rh8 = (void *) kn;

        if (bpf_core_field_exists(kn_rh8->id)) {
            // RHEL8 has both types declared: union and u64:
            //     kn->id
            //     rh->rh_kabi_hidden_172->id
            // pointing to the same data
            bpf_core_read(&id, sizeof(u64), &kn_rh8->id);
        } else {
            // all other regular kernels bellow v5.5
            bpf_core_read(&id, sizeof(u64), &kn_old->id);
        }

    } else {
        // kernel v5.5 and above
        bpf_core_read(&id, sizeof(u64), &kn->id);
    }
#else
    bpf_probe_read(&id, sizeof(u64), &kn->id);
#endif

    return id;
}

static __always_inline const u32 get_cgroup_hierarchy_id(struct cgroup *cgrp)
{
    struct cgroup_root *root = READ_KERN(cgrp->root);
    return READ_KERN(root->hierarchy_id);
}

static __always_inline const u64 get_cgroup_v1_subsys0_id(struct task_struct *task)
{
    struct css_set *cgroups = READ_KERN(task->cgroups);
    struct cgroup_subsys_state *subsys0 = READ_KERN(cgroups->subsys[0]);
    struct cgroup *cgroup = READ_KERN(subsys0->cgroup);
    return get_cgroup_id(cgroup);
}

#endif