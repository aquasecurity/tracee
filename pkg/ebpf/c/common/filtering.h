#ifndef __COMMON_FILTERING_H__
#define __COMMON_FILTERING_H__

#include <vmlinux.h>

#include <maps.h>
#include <common/logging.h>
#include <common/task.h>
#include <common/common.h>

// PROTOTYPES

statfunc void *get_filter_map(void *, rule_key_t *);
statfunc u64 uint_filter_range_matches(u64, void *, u64, u64, u64);
statfunc u64 binary_filter_matches(u64, void *, proc_info_t *);
statfunc u64 equality_filter_matches(u64, void *, void *);
statfunc u64 bool_filter_matches(u64, bool);
statfunc u64 match_rule_filters(program_data_t *);
statfunc bool evaluate_rule_filters(program_data_t *);
statfunc bool event_is_selected(u32, u8);
statfunc bool rules_matched(event_data_t *);

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

// get_filter_map returns the filter map for the given rule key and outer map
statfunc void *get_filter_map(void *outer_map, rule_key_t *key)
{
    return bpf_map_lookup_elem(outer_map, key);
}

statfunc u64
uint_filter_range_matches(u64 filter_out_rules, void *filter_map, u64 value, u64 max, u64 min)
{
    // check equality_filter_matches() for more info

    u64 equal_in_rules = 0;
    u64 equality_set_in_rules = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, &value);
        if (equality != NULL) {
            equal_in_rules = equality->equal_in_rules;
            equality_set_in_rules = equality->equality_set_in_rules;
        }
    }

    if ((max != FILTER_MAX_NOT_SET) && (value >= max))
        return equal_in_rules;

    if ((min != FILTER_MIN_NOT_SET) && (value <= min))
        return equal_in_rules;

    return equal_in_rules | (filter_out_rules & ~equality_set_in_rules);
}

statfunc u64 binary_filter_matches(u64 filter_out_rules, void *filter_map, proc_info_t *proc_info)
{
    // check equality_filter_matches() for more info

    u64 equal_in_rules = 0;
    u64 equality_set_in_rules = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, proc_info->binary.path);
        if (equality == NULL) {
            // lookup by binary path and mount namespace
            equality = bpf_map_lookup_elem(filter_map, &proc_info->binary);
        }
        if (equality != NULL) {
            equal_in_rules = equality->equal_in_rules;
            equality_set_in_rules = equality->equality_set_in_rules;
        }
    }

    return equal_in_rules | (filter_out_rules & ~equality_set_in_rules);
}

statfunc u64 equality_filter_matches(u64 filter_out_rules, void *filter_map, void *key)
{
    // check compute_scopes() for initial info
    //
    //   policy 2: comm=who
    //   policy 3: comm=ping
    //   policy 4: comm!=who
    //
    // filter_out_rules = 0000 1000, since scope 4 has "not equal" for comm filter
    // filter_map        = comm_fltr
    // key               = "who" | "ping"
    //
    // ---
    //
    // considering an event from "who" command
    //
    // equal_in_rules   = 0000 0010, since scope 2 has "equal" for comm filter
    // equality_set_in_rules = 0000 1010, since scope 2 and 4 are set for comm filter
    //
    // return            = equal_in_rules | (filter_out_rules & equality_set_in_rules)
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
    // equal_in_rules   = 0000 0100, since scope 3 has "equal" for comm filter
    // equality_set_in_rules = 0000 0100, since scope 3 is set for comm filter
    //
    // return            = equal_in_rules | (filter_out_rules & ~equality_set_in_rules)
    //                     0000 0100 |
    //                     (0000 1000 & 0000 0100) -> 0000 0000
    //
    //                     0000 0100 |
    //                     0000 0000
    //                     ---------
    //                     0000 0100 = (scope 3 matched)

    u64 equal_in_rules = 0;
    u64 equality_set_in_rules = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, key);
        if (equality != NULL) {
            equal_in_rules = equality->equal_in_rules;
            equality_set_in_rules = equality->equality_set_in_rules;
        }
    }

    return equal_in_rules | (filter_out_rules & ~equality_set_in_rules);
}

statfunc u64 bool_filter_matches(u64 filter_out_rules, bool val)
{
    // check compute_scopes() for initial info
    //
    //   policy 5: container=true
    //
    // considering an event from a container
    //
    //   filter_out_rules = 0000 0000
    //   val               = true
    //   return            = 0000 0000 ^
    //                       1111 1111 <- ~0ULL
    //                       ---------
    //                       1111 1111
    //
    // considering an event not from a container
    //
    //   filter_out_rules = 0000 0000
    //   val               = false
    //   return            = 0000 0000 ^
    //                       0000 0000
    //                       ---------
    //                       0000 0000

    return filter_out_rules ^ (val ? ~0ULL : 0);
}

statfunc u64 match_rule_filters(program_data_t *p)
{
    task_context_t *context = &p->event->context.task;

    // Don't monitor self
    if (p->config->tracee_pid == context->host_pid)
        return 0;

    proc_info_t *proc_info = p->proc_info;
    rules_config_t *rules_cfg = &p->event->config.rules_config;
    u64 res = ~0ULL;

    //
    // boolean filters (not using versioned filter maps)
    //

    if (rules_cfg->cont_filter_enabled) {
        bool is_container = false;
        u8 state = p->task_info->container_state;
        if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
            is_container = true;
        u64 filter_out_rules = rules_cfg->cont_filter_out;
        u64 mask = ~rules_cfg->cont_filter_enabled;

        // For scopes which has this filter disabled we want to set the matching bits using 'mask'
        res &= bool_filter_matches(filter_out_rules, is_container) | mask;
    }

    if (rules_cfg->new_cont_filter_enabled) {
        bool is_new_container = false;
        if (p->task_info->container_state == CONTAINER_STARTED)
            is_new_container = true;
        u64 filter_out_rules = rules_cfg->new_cont_filter_out;
        u64 mask = ~rules_cfg->new_cont_filter_enabled;

        res &= bool_filter_matches(filter_out_rules, is_new_container) | mask;
    }

    if (rules_cfg->new_pid_filter_enabled) {
        u64 filter_out_rules = rules_cfg->new_pid_filter_out;
        u64 mask = ~rules_cfg->new_pid_filter_enabled;

        res &= bool_filter_matches(filter_out_rules, proc_info->new_proc) | mask;
    }

    //
    // equality filters (using versioned filter maps)
    //

    // u16 version = p->event->context.policies_version;
    rule_key_t rkey = {
        .event_id = p->event->context.eventid,
        .rules_id = p->event->context.rules_id,
    };
    void *filter_map = NULL;

    if (rules_cfg->pid_filter_enabled) {
        u64 filter_out_rules = rules_cfg->pid_filter_out;
        u64 mask = ~rules_cfg->pid_filter_enabled;
        u64 max = rules_cfg->pid_max;
        u64 min = rules_cfg->pid_min;

        filter_map = get_filter_map(&pid_fltr_outer, &rkey);
        // the user might have given us a tid - check for it too
        res &=
            uint_filter_range_matches(filter_out_rules, filter_map, context->host_pid, max, min) |
            uint_filter_range_matches(filter_out_rules, filter_map, context->host_tid, max, min) |
            mask;
    }

    if (rules_cfg->uid_filter_enabled) {
        context->uid = bpf_get_current_uid_gid();
        u64 filter_out_rules = rules_cfg->uid_filter_out;
        u64 mask = ~rules_cfg->uid_filter_enabled;
        u64 max = rules_cfg->uid_max;
        u64 min = rules_cfg->uid_min;

        filter_map = get_filter_map(&uid_fltr_outer, &rkey);
        res &=
            uint_filter_range_matches(filter_out_rules, filter_map, context->uid, max, min) | mask;
    }

    if (rules_cfg->mnt_ns_filter_enabled) {
        context->mnt_id = get_task_mnt_ns_id(p->event->task);
        u64 filter_out_rules = rules_cfg->mnt_ns_filter_out;
        u64 mask = ~rules_cfg->mnt_ns_filter_enabled;

        filter_map = get_filter_map(&mntns_fltr_outer, &rkey);
        res &= equality_filter_matches(filter_out_rules, filter_map, &context->mnt_id) | mask;
    }

    if (rules_cfg->pid_ns_filter_enabled) {
        context->pid_id = get_task_pid_ns_id(p->event->task);
        u64 filter_out_rules = rules_cfg->pid_ns_filter_out;
        u64 mask = ~rules_cfg->pid_ns_filter_enabled;

        filter_map = get_filter_map(&pidns_fltr_outer, &rkey);
        res &= equality_filter_matches(filter_out_rules, filter_map, &context->pid_id) | mask;
    }

    if (rules_cfg->uts_ns_filter_enabled) {
        char *uts_name = get_task_uts_name(p->event->task);
        if (uts_name)
            bpf_probe_read_kernel_str(&context->uts_name, TASK_COMM_LEN, uts_name);
        u64 filter_out_rules = rules_cfg->uts_ns_filter_out;
        u64 mask = ~rules_cfg->uts_ns_filter_enabled;

        filter_map = get_filter_map(&utsns_fltr_outer, &rkey);
        res &= equality_filter_matches(filter_out_rules, filter_map, &context->uts_name) | mask;
    }

    if (rules_cfg->comm_filter_enabled) {
        bpf_get_current_comm(&context->comm, sizeof(context->comm));
        u64 filter_out_rules = rules_cfg->comm_filter_out;
        u64 mask = ~rules_cfg->comm_filter_enabled;

        filter_map = get_filter_map(&comm_fltr_outer, &rkey);
        res &= equality_filter_matches(filter_out_rules, filter_map, &context->comm) | mask;
    }

    if (rules_cfg->cgroup_id_filter_enabled) {
        u32 cgroup_id_lsb = context->cgroup_id;
        u64 filter_out_rules = rules_cfg->cgroup_id_filter_out;
        u64 mask = ~rules_cfg->cgroup_id_filter_enabled;

        filter_map = get_filter_map(&cgrpid_fltr_outer, &rkey);
        res &= equality_filter_matches(filter_out_rules, filter_map, &cgroup_id_lsb) | mask;
    }

    if (rules_cfg->proc_tree_filter_enabled) {
        u64 filter_out_rules = rules_cfg->proc_tree_filter_out;
        u64 mask = ~rules_cfg->proc_tree_filter_enabled;

        filter_map = get_filter_map(&ptree_fltr_outer, &rkey);
        res &= equality_filter_matches(filter_out_rules, filter_map, &context->host_pid) | mask;
    }

    if (rules_cfg->bin_path_filter_enabled) {
        u64 filter_out_rules = rules_cfg->bin_path_filter_out;
        u64 mask = ~rules_cfg->bin_path_filter_enabled;

        filter_map = get_filter_map(&bin_fltr_outer, &rkey);
        res &= binary_filter_matches(filter_out_rules, filter_map, proc_info) | mask;
    }

    //
    // follow filter
    //

    if (rules_cfg->follow_filter_enabled) {
        // trace this proc anyway if follow was set by a scope
        res |= proc_info->follow_in_rules & rules_cfg->follow_filter_enabled;
    }

    // Make sure only enabled scopes are set in the bitmask (other bits are invalid)
    return res & rules_cfg->enabled;
}

statfunc bool evaluate_rule_filters(program_data_t *p)
{
    u64 matched_rules = match_rule_filters(p);
    p->event->context.matched_rules &= matched_rules;
    return p->event->context.matched_rules != 0;
}

statfunc bool rules_matched(event_data_t *event)
{
    return event->context.matched_rules != 0;
}

statfunc bool event_is_selected(u32 event_id, u8 rules_id)
{
    rule_key_t key = {
        .event_id = event_id,
        .rules_id = rules_id,
    };
    event_config_t *event_config = bpf_map_lookup_elem(&events_map, &key);
    if (event_config == NULL)
        return 0;

    return event_config->submit_for_rules != 0;
}

statfunc u64 get_rules_to_follow(program_data_t *p)
{
    return match_rule_filters(p);
}

#endif
