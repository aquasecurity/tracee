#ifndef __COMMON_FILTERING_H__
#define __COMMON_FILTERING_H__

#include <vmlinux.h>

#include <maps.h>
#include <common/logging.h>
#include <common/task.h>
#include <common/common.h>

// PROTOTYPES

statfunc void *get_filter_map(void *, u16);
statfunc u64 uint_filter_range_matches(u64, void *, u64, u64, u64);
statfunc u64 binary_filter_matches(u64, void *, proc_info_t *);
statfunc u64 equality_filter_matches(u64, void *, void *);
statfunc u64 bool_filter_matches(u64, bool);
statfunc u64 match_scope_filters(program_data_t *);
statfunc bool evaluate_scope_filters(program_data_t *);
statfunc bool event_is_selected(u32, u16);
statfunc bool policies_matched(event_data_t *);

// CONSTANTS

#define FILTER_MAX_NOT_SET 0
#define FILTER_MIN_NOT_SET ULLONG_MAX

// FUNCTIONS

// get_filter_map returns the filter map for the given version and outer map
statfunc void *get_filter_map(void *outer_map, u16 version)
{
    return bpf_map_lookup_elem(outer_map, &version);
}

statfunc u64
uint_filter_range_matches(u64 match_if_key_missing, void *filter_map, u64 value, u64 max, u64 min)
{
    // check equality_filter_matches() for more info

    u64 equals_in_policies = 0;
    u64 key_used_in_policies = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, &value);
        if (equality != NULL) {
            equals_in_policies = equality->equals_in_policies;
            key_used_in_policies = equality->key_used_in_policies;
        }
    }

    if ((max != FILTER_MAX_NOT_SET) && (value >= max))
        return equals_in_policies;

    if ((min != FILTER_MIN_NOT_SET) && (value <= min))
        return equals_in_policies;

    return equals_in_policies | (match_if_key_missing & ~key_used_in_policies);
}

statfunc u64 binary_filter_matches(u64 match_if_key_missing,
                                   void *filter_map,
                                   proc_info_t *proc_info)
{
    // check equality_filter_matches() for more info

    u64 equals_in_policies = 0;
    u64 key_used_in_policies = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, proc_info->binary.path);
        if (equality == NULL) {
            // lookup by binary path and mount namespace
            equality = bpf_map_lookup_elem(filter_map, &proc_info->binary);
        }
        if (equality != NULL) {
            equals_in_policies = equality->equals_in_policies;
            key_used_in_policies = equality->key_used_in_policies;
        }
    }

    return equals_in_policies | (match_if_key_missing & ~key_used_in_policies);
}

statfunc u64 equality_filter_matches(u64 match_if_key_missing, void *filter_map, void *key)
{
    // check match_scope_filters() for initial info
    //
    //   policy 2: comm=who
    //   policy 3: comm=ping
    //   policy 4: comm!=who
    //
    // match_if_key_missing = 0000 1000, since policy 4 has "not equal" for comm filter
    // filter_map        = comm_filter
    // key               = "who" | "ping"
    //
    // ---
    //
    // considering an event from "who" command
    //
    // equals_in_policies   = 0000 0010, since policy 2 has "equal" for comm filter
    // key_used_in_policies = 0000 1010, since policy 2 and 4 are using the key "who"
    //
    // return            = equals_in_policies | (match_if_key_missing & ~key_used_in_policies)
    //                     0000 0010 |
    //                     (0000 1000 & 1111 0101) -> 0000 0000
    //
    //                     0000 0010 |
    //                     0000 0000
    //                     ---------
    //                     0000 0010 = (policy 2 matched)
    //
    // considering an event from "ping" command
    //
    // equals_in_policies   = 0000 0100, since policy 3 has "equal" for comm filter
    // key_used_in_policies = 0000 0100, since policy 3 is set for comm filter
    //
    // return            = equals_in_policies | (match_if_key_missing & ~key_used_in_policies)
    //                     0000 0100 |
    //                     (0000 1000 & 1111 1011) -> 0000 1000
    //
    //                     0000 0100 |
    //                     0000 1000
    //                     ---------
    //                     0000 1100 = (policy 3 and 4 matched)

    u64 equals_in_policies = 0;
    u64 key_used_in_policies = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, key);
        if (equality != NULL) {
            equals_in_policies = equality->equals_in_policies;
            key_used_in_policies = equality->key_used_in_policies;
        }
    }

    // match if:
    // 1. key is used and equality matches (equals_in_policies)
    // 2. key is NOT used and the default action is to match
    return equals_in_policies | (match_if_key_missing & ~key_used_in_policies);
}

statfunc u64 bool_filter_matches(u64 match_bitmap, bool bool_value)
{
    // check match_scope_filters() for initial info
    //
    //   policy 5: container=true
    //
    // considering an event from a container
    //
    //   match_bitmap         = 0000 0000
    //   val                  = true
    //   return               = 0000 0000 ^
    //                          1111 1111 <- ~0ULL
    //                          ---------
    //                          1111 1111
    //
    // considering an event not from a container
    //
    //   match_bitmap         = 0000 0000
    //   val                  = false
    //   return               = 0000 0000 ^
    //                          0000 0000
    //                          ---------
    //                          0000 0000

    return match_bitmap ^ (bool_value ? ~0ULL : 0);
}

statfunc u64 match_scope_filters(program_data_t *p)
{
    task_context_t *context = &p->event->context.task;

    // Don't monitor self
    if (p->config->tracee_pid == context->host_pid)
        return 0;

    proc_info_t *proc_info = p->proc_info;
    policies_config_t *policies_cfg = &p->event->policies_config;
    u64 res = ~0ULL;

    //
    // boolean filters (not using versioned filter maps)
    //

    if (policies_cfg->cont_filter_enabled) {
        bool is_container = false;
        u8 state = p->task_info->container_state;
        if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
            is_container = true;
        u64 match_bitmap = policies_cfg->cont_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->cont_filter_enabled;

        // For policies that have this filter disabled we want to set the matching bits using 'mask'
        res &= bool_filter_matches(match_bitmap, is_container) | mask;
    }

    if (policies_cfg->new_cont_filter_enabled) {
        bool is_new_container = false;
        if (p->task_info->container_state == CONTAINER_STARTED)
            is_new_container = true;
        u64 match_bitmap = policies_cfg->new_cont_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->new_cont_filter_enabled;

        res &= bool_filter_matches(match_bitmap, is_new_container) | mask;
    }

    if (policies_cfg->new_pid_filter_enabled) {
        u64 match_bitmap = policies_cfg->new_pid_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->new_pid_filter_enabled;

        res &= bool_filter_matches(match_bitmap, proc_info->new_proc) | mask;
    }

    //
    // equality filters (using versioned filter maps)
    //

    u16 version = p->event->context.policies_version;
    void *filter_map = NULL;

    if (policies_cfg->pid_filter_enabled) {
        u64 match_if_key_missing = policies_cfg->pid_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->pid_filter_enabled;
        u64 max = policies_cfg->pid_max;
        u64 min = policies_cfg->pid_min;

        filter_map = get_filter_map(&pid_filter_version, version);
        // the user might have given us a tid - check for it too
        res &= uint_filter_range_matches(
                   match_if_key_missing, filter_map, context->host_pid, max, min) |
               uint_filter_range_matches(
                   match_if_key_missing, filter_map, context->host_tid, max, min) |
               mask;
    }

    if (policies_cfg->uid_filter_enabled) {
        context->uid = bpf_get_current_uid_gid();
        u64 match_if_key_missing = policies_cfg->uid_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->uid_filter_enabled;
        u64 max = policies_cfg->uid_max;
        u64 min = policies_cfg->uid_min;

        filter_map = get_filter_map(&uid_filter_version, version);
        res &= uint_filter_range_matches(match_if_key_missing, filter_map, context->uid, max, min) |
               mask;
    }

    if (policies_cfg->mnt_ns_filter_enabled) {
        context->mnt_id = get_task_mnt_ns_id(p->event->task);
        u64 match_if_key_missing = policies_cfg->mnt_ns_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->mnt_ns_filter_enabled;

        filter_map = get_filter_map(&mnt_ns_filter_version, version);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->mnt_id) | mask;
    }

    if (policies_cfg->pid_ns_filter_enabled) {
        context->pid_id = get_task_pid_ns_id(p->event->task);
        u64 match_if_key_missing = policies_cfg->pid_ns_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->pid_ns_filter_enabled;

        filter_map = get_filter_map(&pid_ns_filter_version, version);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->pid_id) | mask;
    }

    if (policies_cfg->uts_ns_filter_enabled) {
        char *uts_name = get_task_uts_name(p->event->task);
        if (uts_name)
            bpf_probe_read_kernel_str(&context->uts_name, TASK_COMM_LEN, uts_name);
        u64 match_if_key_missing = policies_cfg->uts_ns_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->uts_ns_filter_enabled;

        filter_map = get_filter_map(&uts_ns_filter_version, version);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->uts_name) | mask;
    }

    if (policies_cfg->comm_filter_enabled) {
        bpf_get_current_comm(&context->comm, sizeof(context->comm));
        u64 match_if_key_missing = policies_cfg->comm_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->comm_filter_enabled;

        filter_map = get_filter_map(&comm_filter_version, version);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->comm) | mask;
    }

    if (policies_cfg->cgroup_id_filter_enabled) {
        u32 cgroup_id_lsb = context->cgroup_id;
        u64 match_if_key_missing = policies_cfg->cgroup_id_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->cgroup_id_filter_enabled;

        filter_map = get_filter_map(&cgroup_id_filter_version, version);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &cgroup_id_lsb) | mask;
    }

    if (policies_cfg->proc_tree_filter_enabled) {
        u64 match_if_key_missing = policies_cfg->proc_tree_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->proc_tree_filter_enabled;

        filter_map = get_filter_map(&process_tree_map_version, version);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->host_pid) | mask;
    }

    if (policies_cfg->bin_path_filter_enabled) {
        u64 match_if_key_missing = policies_cfg->bin_path_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->bin_path_filter_enabled;

        filter_map = get_filter_map(&binary_filter_version, version);
        res &= binary_filter_matches(match_if_key_missing, filter_map, proc_info) | mask;
    }

    //
    // follow filter
    //

    if (policies_cfg->follow_filter_enabled) {
        // trace this proc anyway if follow was set by a scope
        res |= proc_info->follow_in_scopes & policies_cfg->follow_filter_enabled;
    }

    // Make sure only enabled policies are set in the bitmap (other bits are invalid)
    return res & policies_cfg->enabled_policies;
}

statfunc bool evaluate_scope_filters(program_data_t *p)
{
    u64 matched_policies = match_scope_filters(p);
    p->event->context.matched_policies &= matched_policies;
    return p->event->context.matched_policies != 0;
}

statfunc bool policies_matched(event_data_t *event)
{
    return event->context.matched_policies != 0;
}

statfunc bool event_is_selected(u32 event_id, u16 policies_version)
{
    void *inner_events_map = bpf_map_lookup_elem(&events_map_version, &policies_version);
    if (inner_events_map == NULL)
        return 0;

    event_config_t *event_config = bpf_map_lookup_elem(inner_events_map, &event_id);
    if (event_config == NULL)
        return 0;

    return event_config->submit_for_policies != 0;
}

statfunc u64 get_scopes_to_follow(program_data_t *p)
{
    return match_scope_filters(p);
}

#endif
