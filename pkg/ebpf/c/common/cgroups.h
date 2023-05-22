#ifndef __COMMON_CGROUPS_H__
#define __COMMON_CGROUPS_H__

#include <vmlinux.h>
#include <vmlinux_flavors.h>

#include <common/common.h>

// PROTOTYPES

statfunc const char *get_cgroup_dirname(struct cgroup *);
statfunc const u64 get_cgroup_id(struct cgroup *);
statfunc const u32 get_cgroup_hierarchy_id(struct cgroup *);
statfunc const u64 get_cgroup_v1_subsys0_id(struct task_struct *);

// FUNCTIONS

statfunc const char *get_cgroup_dirname(struct cgroup *cgrp)
{
    struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);

    if (kn == NULL)
        return NULL;

    return BPF_CORE_READ(kn, name);
}

statfunc const u64 get_cgroup_id(struct cgroup *cgrp)
{
    struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);

    if (kn == NULL)
        return 0;

    u64 id; // was union kernfs_node_id before 5.5, can read it as u64 in both situations

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

    return id;
}

statfunc const u32 get_cgroup_hierarchy_id(struct cgroup *cgrp)
{
    struct cgroup_root *root = BPF_CORE_READ(cgrp, root);
    return BPF_CORE_READ(root, hierarchy_id);
}

statfunc const u64 get_cgroup_v1_subsys0_id(struct task_struct *task)
{
    struct css_set *cgroups = BPF_CORE_READ(task, cgroups);
    struct cgroup_subsys_state *subsys0 = BPF_CORE_READ(cgroups, subsys[0]);
    struct cgroup *cgroup = BPF_CORE_READ(subsys0, cgroup);
    return get_cgroup_id(cgroup);
}

#endif
