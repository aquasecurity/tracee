#ifndef __COMMON_FILTERING_H__
#define __COMMON_FILTERING_H__

#include <vmlinux.h>

#include <maps.h>
#include <common/logging.h>
#include <common/common.h>

// PROTOTYPES

statfunc policies_config_t *get_policies_config(program_data_t *);
statfunc void *get_filter_map(void *, u16);
statfunc u64 uint_filter_range_matches(u64, void *, u64, u64, u64);
statfunc u64 binary_filter_matches(u64, void *, proc_info_t *);
statfunc u64 equality_filter_matches(u64, void *, void *);
statfunc u64 bool_filter_matches(u64, bool);
statfunc u64 compute_scopes(program_data_t *);
statfunc u64 should_trace(program_data_t *);
statfunc u64 should_submit(u32, event_data_t *);

// CONSTANTS

#define FILTER_UID_ENABLED       (1 << 0)
#define FILTER_UID_OUT           (1 << 1)
#define FILTER_MNT_NS_ENABLED    (1 << 2)
#define FILTER_MNT_NS_OUT        (1 << 3)
#define FILTER_PID_NS_ENABLED    (1 << 4)
#define FILTER_PID_NS_OUT        (1 << 5)
#define FILTER_UTS_NS_ENABLED    (1 << 6)
#define FILTER_UTS_NS_OUT        (1 << 7)
#define FILTER_COMM_ENABLED      (1 << 8)
#define FILTER_COMM_OUT          (1 << 9)
#define FILTER_PID_ENABLED       (1 << 10)
#define FILTER_PID_OUT           (1 << 11)
#define FILTER_CONT_ENABLED      (1 << 12)
#define FILTER_CONT_OUT          (1 << 13)
#define FILTER_FOLLOW_ENABLED    (1 << 14)
#define FILTER_NEW_PID_ENABLED   (1 << 15)
#define FILTER_NEW_PID_OUT       (1 << 16)
#define FILTER_NEW_CONT_ENABLED  (1 << 17)
#define FILTER_NEW_CONT_OUT      (1 << 18)
#define FILTER_PROC_TREE_ENABLED (1 << 19)
#define FILTER_PROC_TREE_OUT     (1 << 20)
#define FILTER_CGROUP_ID_ENABLED (1 << 21)
#define FILTER_CGROUP_ID_OUT     (1 << 22)
#define FILTER_BIN_PATH_ENABLED  (1 << 23)
#define FILTER_BIN_PATH_OUT      (1 << 24)

#define FILTER_MAX_NOT_SET 0
#define FILTER_MIN_NOT_SET ULLONG_MAX

// FUNCTIONS

statfunc policies_config_t *get_policies_config(program_data_t *p)
{
    u16 version = p->event->context.policies_version;

    if (likely(version == p->config->policies_version)) {
        return &p->config->policies_config;
    } else {
        policies_config_map_t *policies_config_map;
        policies_config_map = bpf_map_lookup_elem(&policies_config_version, &version);
        if (unlikely(policies_config_map == NULL))
            return NULL;

        u32 zero = 0;
        return bpf_map_lookup_elem(policies_config_map, &zero);
    }
}

// get_filter_map returns the filter map for the given version and outer map
statfunc void *get_filter_map(void *outer_map, u16 version)
{
    return bpf_map_lookup_elem(outer_map, &version);
}

statfunc u64
uint_filter_range_matches(u64 filter_out_scopes, void *filter_map, u64 value, u64 max, u64 min)
{
    // check equality_filter_matches() for more info

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, &value);
        if (equality != NULL) {
            equal_in_scopes = equality->equal_in_scopes;
            equality_set_in_scopes = equality->equality_set_in_scopes;
        }
    }

    if ((max != FILTER_MAX_NOT_SET) && (value >= max))
        return equal_in_scopes;

    if ((min != FILTER_MIN_NOT_SET) && (value <= min))
        return equal_in_scopes;

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

statfunc u64 binary_filter_matches(u64 filter_out_scopes, void *filter_map, proc_info_t *proc_info)
{
    // check equality_filter_matches() for more info

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, proc_info->binary.path);
        if (equality == NULL) {
            // lookup by binary path and mount namespace
            equality = bpf_map_lookup_elem(filter_map, &proc_info->binary);
        }
        if (equality != NULL) {
            equal_in_scopes = equality->equal_in_scopes;
            equality_set_in_scopes = equality->equality_set_in_scopes;
        }
    }

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

statfunc u64 equality_filter_matches(u64 filter_out_scopes, void *filter_map, void *key)
{
    // check compute_scopes() for initial info
    //
    //   policy 2: comm=who
    //   policy 3: comm=ping
    //   policy 4: comm!=who
    //
    // filter_out_scopes = 0000 1000, since scope 4 has "not equal" for comm filter
    // filter_map        = comm_filter
    // key               = "who" | "ping"
    //
    // ---
    //
    // considering an event from "who" command
    //
    // equal_in_scopes   = 0000 0010, since scope 2 has "equal" for comm filter
    // equality_set_in_scopes = 0000 1010, since scope 2 and 4 are set for comm filter
    //
    // return            = equal_in_scopes | (filter_out_scopes & equality_set_in_scopes)
    //                     0000 0010 |
    //                     (0000 1000 & 1111 0101) -> 0000 0000
    //
    //                     0000 0010 |
    //                     0000 0000
    //                     ---------
    //                     0000 0010 = (scope 2 matched)
    //
    // considering an event from "ping" command
    //
    // equal_in_scopes   = 0000 0100, since scope 3 has "equal" for comm filter
    // equality_set_in_scopes = 0000 0100, since scope 3 is set for comm filter
    //
    // return            = equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes)
    //                     0000 0100 |
    //                     (0000 1000 & 0000 0100) -> 0000 0000
    //
    //                     0000 0100 |
    //                     0000 0000
    //                     ---------
    //                     0000 0100 = (scope 3 matched)

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, key);
        if (equality != NULL) {
            equal_in_scopes = equality->equal_in_scopes;
            equality_set_in_scopes = equality->equality_set_in_scopes;
        }
    }

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

statfunc u64 bool_filter_matches(u64 filter_out_scopes, bool val)
{
    // check compute_scopes() for initial info
    //
    //   policy 5: container=true
    //
    // considering an event from a container
    //
    //   filter_out_scopes = 0000 0000
    //   val               = true
    //   return            = 0000 0000 ^
    //                       1111 1111 <- ~0ULL
    //                       ---------
    //                       1111 1111
    //
    // considering an event not from a container
    //
    //   filter_out_scopes = 0000 0000
    //   val               = false
    //   return            = 0000 0000 ^
    //                       0000 0000
    //                       ---------
    //                       0000 0000

    return filter_out_scopes ^ (val ? ~0ULL : 0);
}

statfunc u64 compute_scopes(program_data_t *p)
{
    task_context_t *context = &p->task_info->context;

    // Don't monitor self
    if (p->config->tracee_pid == context->host_pid)
        return 0;

    proc_info_t *proc_info = p->proc_info;

    policies_config_t *policies_cfg = get_policies_config(p);
    if (unlikely(policies_cfg == NULL)) {
        // policies_config should be set by userland
        return 0;
    }

    u64 res = ~0ULL;

    //
    // boolean filters (not using versioned filter maps)
    //

    if (policies_cfg->cont_filter_enabled_scopes) {
        bool is_container = false;
        u8 state = p->task_info->container_state;
        if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
            is_container = true;
        u64 filter_out_scopes = policies_cfg->cont_filter_out_scopes;
        u64 mask = ~policies_cfg->cont_filter_enabled_scopes;

        // For scopes which has this filter disabled we want to set the matching bits using 'mask'
        res &= bool_filter_matches(filter_out_scopes, is_container) | mask;
    }

    if (policies_cfg->new_cont_filter_enabled_scopes) {
        bool is_new_container = false;
        if (p->task_info->container_state == CONTAINER_STARTED)
            is_new_container = true;
        u64 filter_out_scopes = policies_cfg->new_cont_filter_out_scopes;
        u64 mask = ~policies_cfg->new_cont_filter_enabled_scopes;

        res &= bool_filter_matches(filter_out_scopes, is_new_container) | mask;
    }

    if (policies_cfg->new_pid_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->new_pid_filter_out_scopes;
        u64 mask = ~policies_cfg->new_pid_filter_enabled_scopes;

        res &= bool_filter_matches(filter_out_scopes, proc_info->new_proc) | mask;
    }

    //
    // equality filters (using versioned filter maps)
    //

    u16 version = p->event->context.policies_version;
    void *filter_map = NULL;

    if (policies_cfg->pid_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->pid_filter_out_scopes;
        u64 mask = ~policies_cfg->pid_filter_enabled_scopes;
        u64 max = policies_cfg->pid_max;
        u64 min = policies_cfg->pid_min;

        filter_map = get_filter_map(&pid_filter_version, version);
        // the user might have given us a tid - check for it too
        res &=
            uint_filter_range_matches(filter_out_scopes, filter_map, context->host_pid, max, min) |
            uint_filter_range_matches(filter_out_scopes, filter_map, context->host_tid, max, min) |
            mask;
    }

    if (policies_cfg->uid_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->uid_filter_out_scopes;
        u64 mask = ~policies_cfg->uid_filter_enabled_scopes;
        u64 max = policies_cfg->uid_max;
        u64 min = policies_cfg->uid_min;

        filter_map = get_filter_map(&uid_filter_version, version);
        res &=
            uint_filter_range_matches(filter_out_scopes, filter_map, context->uid, max, min) | mask;
    }

    if (policies_cfg->mnt_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->mnt_ns_filter_out_scopes;
        u64 mask = ~policies_cfg->mnt_ns_filter_enabled_scopes;
        u64 mnt_id = context->mnt_id;

        filter_map = get_filter_map(&mnt_ns_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &mnt_id) | mask;
    }

    if (policies_cfg->pid_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->pid_ns_filter_out_scopes;
        u64 mask = ~policies_cfg->pid_ns_filter_enabled_scopes;
        u64 pid_id = context->pid_id;

        filter_map = get_filter_map(&pid_ns_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &pid_id) | mask;
    }

    if (policies_cfg->uts_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->uts_ns_filter_out_scopes;
        u64 mask = ~policies_cfg->uts_ns_filter_enabled_scopes;

        filter_map = get_filter_map(&uts_ns_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &context->uts_name) | mask;
    }

    if (policies_cfg->comm_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->comm_filter_out_scopes;
        u64 mask = ~policies_cfg->comm_filter_enabled_scopes;

        filter_map = get_filter_map(&comm_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &context->comm) | mask;
    }

    if (policies_cfg->cgroup_id_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->cgroup_id_filter_out_scopes;
        u64 mask = ~policies_cfg->cgroup_id_filter_enabled_scopes;
        u32 cgroup_id_lsb = context->cgroup_id;

        filter_map = get_filter_map(&cgroup_id_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &cgroup_id_lsb) | mask;
    }

    if (policies_cfg->proc_tree_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->proc_tree_filter_out_scopes;
        u64 mask = ~policies_cfg->proc_tree_filter_enabled_scopes;
        u32 host_pid = context->host_pid;

        filter_map = get_filter_map(&process_tree_map_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &host_pid) | mask;
    }

    if (policies_cfg->bin_path_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->bin_path_filter_out_scopes;
        u64 mask = ~policies_cfg->bin_path_filter_enabled_scopes;

        filter_map = get_filter_map(&binary_filter_version, version);
        res &= binary_filter_matches(filter_out_scopes, filter_map, proc_info) | mask;
    }

    //
    // follow filter
    //

    if (policies_cfg->follow_filter_enabled_scopes) {
        // trace this proc anyway if follow was set by a scope
        res |= proc_info->follow_in_scopes & policies_cfg->follow_filter_enabled_scopes;
    }

    // Make sure only enabled scopes are set in the bitmask (other bits are invalid)
    return res & policies_cfg->enabled_scopes;
}

statfunc u64 should_trace(program_data_t *p)
{
    // use cache whenever possible
    if (p->task_info->recompute_scope) {
        p->task_info->matched_scopes = compute_scopes(p);
        p->task_info->recompute_scope = false;
    }

    p->event->context.matched_policies = p->task_info->matched_scopes;

    return p->task_info->matched_scopes;
}

statfunc u64 should_submit(u32 event_id, event_data_t *event)
{
    u16 version = event->context.policies_version;
    void *inner_events_map = bpf_map_lookup_elem(&events_map_version, &version);
    if (inner_events_map == NULL)
        return 0;

    event_config_t *event_config = bpf_map_lookup_elem(inner_events_map, &event_id);
    // if event config not set, don't submit
    if (event_config == NULL)
        return 0;

    // align with previously matched policies
    event->context.matched_policies &= event_config->submit_for_policies;

    // save event's param types
    event->param_types = event_config->param_types;

    return event->context.matched_policies;
}

#endif
