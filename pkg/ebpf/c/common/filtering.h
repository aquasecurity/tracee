#ifndef __FILTERING_H__
#define __FILTERING_H__

#ifndef CORE
    #include <linux/types.h>
#else
    #include <vmlinux.h>
#endif

#include "maps.h"

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

static __always_inline u64
uint_filter_range_matches(u64 filter_out_scopes, void *filter_map, u64 value, u64 max, u64 min)
{
    // check equality_filter_matches() for more info

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;
    eq_t *equality = bpf_map_lookup_elem(filter_map, &value);
    if (equality != NULL) {
        equal_in_scopes = equality->equal_in_scopes;
        equality_set_in_scopes = equality->equality_set_in_scopes;
    }

    if ((max != FILTER_MAX_NOT_SET) && (value >= max))
        return equal_in_scopes;

    if ((min != FILTER_MIN_NOT_SET) && (value <= min))
        return equal_in_scopes;

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

static __always_inline u64 binary_filter_matches(u64 filter_out_scopes, proc_info_t *proc_info)
{
    // check equality_filter_matches() for more info

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;
    eq_t *equality = bpf_map_lookup_elem(&binary_filter, proc_info->binary.path);
    if (equality == NULL) {
        // lookup by binary path and mount namespace
        equality = bpf_map_lookup_elem(&binary_filter, &proc_info->binary);
    }
    if (equality != NULL) {
        equal_in_scopes = equality->equal_in_scopes;
        equality_set_in_scopes = equality->equality_set_in_scopes;
    }

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

static __always_inline u64 equality_filter_matches(u64 filter_out_scopes,
                                                   void *filter_map,
                                                   void *key)
{
    // check compute_scopes() for initial info
    //
    // e.g.: cmdline: -t 2:comm=who -t 3:comm=ping -t 4:comm!=who
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
    eq_t *equality = bpf_map_lookup_elem(filter_map, key);
    if (equality != NULL) {
        equal_in_scopes = equality->equal_in_scopes;
        equality_set_in_scopes = equality->equality_set_in_scopes;
    }

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

static __always_inline u64 bool_filter_matches(u64 filter_out_scopes, bool val)
{
    // check compute_scopes() for initial info
    //
    // e.g.: cmdline: -t 5:container
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

static __always_inline u64 compute_scopes(program_data_t *p)
{
    task_context_t *context = &p->task_info->context;
    u64 res = ~0ULL;

    // Don't monitor self
    if (p->config->tracee_pid == context->host_pid) {
        return 0;
    }

    proc_info_t *proc_info = bpf_map_lookup_elem(&proc_info_map, &context->host_pid);
    if (proc_info == NULL) {
        // entry should exist in proc_map (init_program_data should have set it otherwise)
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(p->event->ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return 0;
    }

    if (p->config->cont_filter_enabled_scopes) {
        bool is_container = false;
        u8 state = p->task_info->container_state;
        if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
            is_container = true;
        u64 filter_out_scopes = p->config->cont_filter_out_scopes;
        u64 mask = ~p->config->cont_filter_enabled_scopes;
        // For scopes which has this filter disabled we want to set the matching bits using 'mask'
        res &= bool_filter_matches(filter_out_scopes, is_container) | mask;
    }

    if (p->config->new_cont_filter_enabled_scopes) {
        bool is_new_container = false;
        if (p->task_info->container_state == CONTAINER_STARTED)
            is_new_container = true;
        u64 filter_out_scopes = p->config->new_cont_filter_out_scopes;
        u64 mask = ~p->config->new_cont_filter_enabled_scopes;
        res &= bool_filter_matches(filter_out_scopes, is_new_container) | mask;
    }

    if (p->config->pid_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->pid_filter_out_scopes;
        u64 mask = ~p->config->pid_filter_enabled_scopes;
        u64 max = p->config->pid_max;
        u64 min = p->config->pid_min;
        // the user might have given us a tid - check for it too
        res &=
            uint_filter_range_matches(filter_out_scopes, &pid_filter, context->host_pid, max, min) |
            uint_filter_range_matches(filter_out_scopes, &pid_filter, context->host_tid, max, min) |
            mask;
    }

    if (p->config->new_pid_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->new_pid_filter_out_scopes;
        u64 mask = ~p->config->new_pid_filter_enabled_scopes;
        res &= bool_filter_matches(filter_out_scopes, proc_info->new_proc) | mask;
    }

    if (p->config->uid_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->uid_filter_out_scopes;
        u64 mask = ~p->config->uid_filter_enabled_scopes;
        u64 max = p->config->uid_max;
        u64 min = p->config->uid_min;
        res &= uint_filter_range_matches(filter_out_scopes, &uid_filter, context->uid, max, min) |
               mask;
    }

    if (p->config->mnt_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->mnt_ns_filter_out_scopes;
        u64 mask = ~p->config->mnt_ns_filter_enabled_scopes;
        u32 mnt_id = context->mnt_id;
        res &= equality_filter_matches(filter_out_scopes, &mnt_ns_filter, &mnt_id) | mask;
    }

    if (p->config->pid_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->pid_ns_filter_out_scopes;
        u64 mask = ~p->config->pid_ns_filter_enabled_scopes;
        u32 pid_id = context->pid_id;
        res &= equality_filter_matches(filter_out_scopes, &pid_ns_filter, &pid_id) | mask;
    }

    if (p->config->uts_ns_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->uts_ns_filter_out_scopes;
        u64 mask = ~p->config->uts_ns_filter_enabled_scopes;
        res &=
            equality_filter_matches(filter_out_scopes, &uts_ns_filter, &context->uts_name) | mask;
    }

    if (p->config->comm_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->comm_filter_out_scopes;
        u64 mask = ~p->config->comm_filter_enabled_scopes;
        res &= equality_filter_matches(filter_out_scopes, &comm_filter, &context->comm) | mask;
    }

    if (p->config->proc_tree_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->proc_tree_filter_out_scopes;
        u64 mask = ~p->config->proc_tree_filter_enabled_scopes;
        res &= equality_filter_matches(filter_out_scopes, &process_tree_map, &context->host_pid) |
               mask;
    }

    if (p->config->cgroup_id_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->cgroup_id_filter_out_scopes;
        u64 mask = ~p->config->cgroup_id_filter_enabled_scopes;
        u64 cgroup_id_lsb = context->cgroup_id;
        res &= equality_filter_matches(filter_out_scopes, &cgroup_id_filter, &cgroup_id_lsb) | mask;
    }

    if (p->config->bin_path_filter_enabled_scopes) {
        u64 filter_out_scopes = p->config->bin_path_filter_out_scopes;
        u64 mask = ~p->config->bin_path_filter_enabled_scopes;
        res &= binary_filter_matches(filter_out_scopes, proc_info) | mask;
    }

    if (p->config->follow_filter_enabled_scopes) {
        // trace this proc anyway if follow was set by a scope
        res |= proc_info->follow_in_scopes & p->config->follow_filter_enabled_scopes;
    }

    // Make sure only enabled scopes are set in the bitmask (other bits are invalid)
    return res & p->config->enabled_scopes;
}

static __always_inline u64 should_trace(program_data_t *p)
{
    // use cache whenever possible
    if (p->task_info->recompute_scope) {
        p->task_info->matched_scopes = compute_scopes(p);
        p->task_info->recompute_scope = false;
    }

    p->event->context.matched_scopes = p->task_info->matched_scopes;

    return p->task_info->matched_scopes;
}

static __always_inline u64 should_submit(u32 event_id, event_context_t *ctx)
{
    // use a map only with no submit cache from config.
    // since this function is only ever called after a should_trace
    // and in the context of a submit program/tail_call, any preemptive
    // cache calculation before checking the map will 99% of times be
    // redundant.
    // a probe/tail call attach almost always implies at least one
    // scope requires the event to be submitted.
    u64 *event_scopes = bpf_map_lookup_elem(&events_map, &event_id);
    // if scopes not set, don't submit
    if (event_scopes == NULL) {
        return 0;
    }

    // align with previously matched scopes
    ctx->matched_scopes &= *event_scopes;

    return ctx->matched_scopes;
}

#endif